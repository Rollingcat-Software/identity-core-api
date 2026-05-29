package com.fivucsas.identity.security;

import com.fivucsas.identity.repository.JpaTenantRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.UUID;

/**
 * Shared helper that maps the currently-authenticated caller to the tenant
 * scope they are allowed to enumerate.
 *
 * <p>Extracted from {@link com.fivucsas.identity.application.service.ManageUserService}
 * (PR #23) so the same pattern is applied consistently across controllers/services
 * that expose listing endpoints — audit logs, enrollments, devices, auth flows,
 * guests, etc.</p>
 *
 * <p><b>Contract:</b></p>
 * <ul>
 *   <li>SUPER_ADMIN / ROOT → returns {@code null}, meaning "no scope restriction,
 *       caller may see data from every tenant".</li>
 *   <li>Any other authenticated user with a tenant → returns the caller's
 *       tenant ID; the caller may only see rows matching that tenant.</li>
 *   <li>Caller without a resolvable tenant (anonymous, broken principal,
 *       deleted user) → returns {@link #FAIL_CLOSED_EMPTY_SCOPE}, a zero-UUID
 *       sentinel that matches no tenant. This keeps the query shape
 *       consistent (one branch) while returning an empty list rather than
 *       unbounded data.</li>
 * </ul>
 *
 * <p><b>SUPER_ADMIN tenant switcher ({@value #ACTIVE_TENANT_HEADER}):</b> a
 * SUPER_ADMIN / ROOT caller may scope every admin list view to one selected
 * tenant by sending the optional {@value #ACTIVE_TENANT_HEADER} request header
 * carrying that tenant's UUID. When present and valid, {@link #currentScope()}
 * resolves to THAT tenant instead of {@code null} (cross-tenant), so Users /
 * Audit-Logs / Sessions / Devices / Enrollments / Auth-Flows / Email-Domains
 * all narrow to the selected tenant in lock-step.</p>
 *
 * <p><b>This is a cross-tenant access-control surface.</b> The override is
 * applied ONLY when {@link RbacAuthorizationService#isSuperAdmin()} is true.
 * For ANY non-ROOT caller the header is ignored outright — they always get
 * their home tenant — so a TENANT_ADMIN or USER can never read another
 * tenant's data by spoofing the header. Absent / blank / malformed / unknown
 * tenant id all fall back to today's behaviour (home tenant for scoped
 * callers, {@code null} cross-tenant for SUPER_ADMIN).</p>
 *
 * <p><b>Why not reuse {@link AuthorizationService#getCurrentTenantId()}?</b>
 * Historically the Spring principal was a plain
 * {@link org.springframework.security.core.userdetails.UserDetails} (not
 * {@code CustomUserDetails}), so {@code getCurrentTenantId()} silently
 * returned {@code null} and would re-open the cross-tenant leak. Fixed in
 * the PR that wires {@code CustomUserDetails} as the authenticated principal
 * (CustomUserDetailsService now constructs CustomUserDetails directly). This
 * resolver still routes through the DB ({@link RbacAuthorizationService#getCurrentUser()})
 * to keep tenant scope decisions independent of cached principal state.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TenantScopeResolver {

    /**
     * Zero-UUID sentinel used when the caller cannot be resolved to a tenant.
     * Matches no tenant row, so queries return empty results instead of
     * unbounded or cross-tenant data.
     */
    public static final UUID FAIL_CLOSED_EMPTY_SCOPE = new UUID(0L, 0L);

    /**
     * Optional request header that lets a SUPER_ADMIN / ROOT caller scope all
     * admin list views to one selected tenant (the "tenant switcher").
     * Ignored for every non-ROOT caller.
     */
    public static final String ACTIVE_TENANT_HEADER = "X-Active-Tenant";

    private final RbacAuthorizationService rbacService;
    private final JpaTenantRepository tenantRepository;

    /**
     * Returns {@code null} for SUPER_ADMIN callers ("no scope restriction"),
     * the caller's tenant UUID otherwise, or the fail-closed sentinel when
     * no tenant can be resolved.
     *
     * <p>SUPER_ADMIN / ROOT callers may narrow the scope to a single selected
     * tenant by sending the {@value #ACTIVE_TENANT_HEADER} header — see the
     * class Javadoc. The header is authoritatively ignored for everyone else.</p>
     */
    public UUID currentScope() {
        if (rbacService.isSuperAdmin()) {
            // Tenant switcher: only ROOT/SUPER_ADMIN may override the active
            // scope. A valid, known tenant id in the header narrows the scope
            // to that tenant; otherwise stay cross-tenant (null).
            UUID active = resolveActiveTenantOverride();
            return active != null ? active : null;
        }
        // Non-ROOT callers: the X-Active-Tenant header is NEVER honoured —
        // they always resolve to their own home tenant (or fail-closed). This
        // is the line that prevents a TENANT_ADMIN/USER from escalating to
        // another tenant's data by spoofing the header.
        return rbacService.getCurrentUser()
                .map(u -> u.getTenant() != null ? u.getTenant().getId() : FAIL_CLOSED_EMPTY_SCOPE)
                .orElse(FAIL_CLOSED_EMPTY_SCOPE);
    }

    /**
     * Reads and validates the {@value #ACTIVE_TENANT_HEADER} header from the
     * current request. Returns the selected tenant id when the header is
     * present, a well-formed UUID, and resolves to an existing tenant;
     * otherwise {@code null} (meaning "no override — keep default behaviour").
     *
     * <p>MUST only be consulted after the caller has been confirmed to be
     * SUPER_ADMIN/ROOT (see {@link #currentScope()}). It performs no authz of
     * its own beyond existence-checking the tenant.</p>
     */
    private UUID resolveActiveTenantOverride() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes servletAttrs)) {
            // No bound HTTP request (scheduled job, async worker, test without
            // a mocked request context) — no override possible.
            return null;
        }
        HttpServletRequest request = servletAttrs.getRequest();
        String raw = request.getHeader(ACTIVE_TENANT_HEADER);
        if (raw == null || raw.isBlank()) {
            return null;
        }
        UUID candidate;
        try {
            candidate = UUID.fromString(raw.trim());
        } catch (IllegalArgumentException e) {
            log.warn("AUDIT: SUPER_ADMIN tenant switcher ignored — malformed {} header value '{}'",
                    ACTIVE_TENANT_HEADER, raw);
            return null;
        }
        if (!tenantRepository.existsById(candidate)) {
            log.warn("AUDIT: SUPER_ADMIN tenant switcher ignored — unknown tenant id {} in {} header",
                    candidate, ACTIVE_TENANT_HEADER);
            return null;
        }
        log.debug("SUPER_ADMIN tenant switcher active — scoping to tenant {}", candidate);
        return candidate;
    }

    /**
     * Returns true if the caller is allowed to access rows tagged with
     * {@code targetTenantId}. SUPER_ADMIN may access any tenant; everyone
     * else only their own.
     */
    public boolean canAccessTenant(UUID targetTenantId) {
        if (targetTenantId == null) return false;
        UUID scope = currentScope();
        return scope == null || scope.equals(targetTenantId);
    }

    /**
     * Convenience — true when the caller has no scope restriction.
     */
    public boolean isUnrestricted() {
        return currentScope() == null;
    }
}
