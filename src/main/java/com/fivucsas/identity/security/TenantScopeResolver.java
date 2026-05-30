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
 *   <li>ROOT → returns {@code null}, meaning "no scope restriction,
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
 * <p><b>ROOT tenant switcher — UNIFIED on {@value #TENANT_ID_HEADER}.</b>
 * A ROOT caller scopes every admin view to one selected tenant by
 * sending the standard {@value #TENANT_ID_HEADER} request header (the SAME header
 * that drives the Hibernate {@code tenantFilter} on Users/Roles via
 * {@code TenantContextFilter} + {@code TenantBindFromAuthFilter}). When present
 * and valid, {@link #currentScope()} resolves to THAT tenant instead of
 * {@code null} (cross-tenant), so Users / Audit-Logs / Sessions / Devices /
 * Enrollments / Auth-Flows / Email-Domains / Guests all narrow to the selected
 * tenant in lock-step — ONE header switches everything.</p>
 *
 * <p>{@value #ACTIVE_TENANT_HEADER} is kept as a backward-compatible alias for
 * the original partial attempt; if both are present, {@value #TENANT_ID_HEADER}
 * wins (it is the canonical, validated header).</p>
 *
 * <p><b>Default (no header) → cross-tenant ({@code null}) for ROOT.</b>
 * The web switcher always sends {@value #TENANT_ID_HEADER} (defaulting to the
 * admin's home tenant), so in practice ROOT views are always pinned. The
 * absent-header fallback stays {@code null} so the existing cross-tenant code
 * paths (e.g. platform-wide guest listing) are unchanged.</p>
 *
 * <p><b>This is a cross-tenant access-control surface.</b> The override is
 * applied ONLY when {@link RbacAuthorizationService#isRoot()} is true.
 * For ANY non-ROOT caller BOTH headers are ignored outright — they always get
 * their home tenant — so a TENANT_ADMIN or USER can never read another
 * tenant's data by spoofing a header. Absent / blank / malformed / unknown
 * tenant id all fall back to today's behaviour (home tenant for scoped
 * callers, {@code null} cross-tenant for ROOT).</p>
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
     * Canonical request header for the ROOT tenant switcher. This is the
     * SAME header that drives the Hibernate {@code tenantFilter} (Users/Roles),
     * so a single header unifies both scoping layers. Ignored for non-ROOT.
     */
    public static final String TENANT_ID_HEADER = "X-Tenant-ID";

    /**
     * Backward-compatible alias for the original partial attempt. Honoured only
     * when {@link #TENANT_ID_HEADER} is absent. Ignored for non-ROOT.
     */
    public static final String ACTIVE_TENANT_HEADER = "X-Active-Tenant";

    private final RbacAuthorizationService rbacService;
    private final JpaTenantRepository tenantRepository;

    /**
     * Returns {@code null} for ROOT callers ("no scope restriction"),
     * the caller's tenant UUID otherwise, or the fail-closed sentinel when
     * no tenant can be resolved.
     *
     * <p>ROOT callers may narrow the scope to a single selected
     * tenant by sending the {@value #TENANT_ID_HEADER} header (or the
     * {@value #ACTIVE_TENANT_HEADER} alias) — see the class Javadoc. The header
     * is authoritatively ignored for everyone else.</p>
     */
    public UUID currentScope() {
        if (rbacService.isRoot()) {
            // Tenant switcher: only ROOT may override the active
            // scope. A valid, known tenant id in the X-Tenant-ID header (or the
            // X-Active-Tenant alias) narrows the scope to that tenant; otherwise
            // stay cross-tenant (null).
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
     * Reads and validates the active-tenant selection from the current request:
     * the canonical {@value #TENANT_ID_HEADER} header, falling back to the
     * {@value #ACTIVE_TENANT_HEADER} alias only when the canonical one is absent.
     * Returns the selected tenant id when present, a well-formed UUID, and an
     * existing tenant; otherwise {@code null} ("no override — keep default
     * behaviour").
     *
     * <p>MUST only be consulted after the caller has been confirmed to be
     * ROOT (see {@link #currentScope()}). It performs no authz of
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

        // Canonical header wins; X-Active-Tenant only consulted as a fallback.
        String headerName = TENANT_ID_HEADER;
        String raw = request.getHeader(TENANT_ID_HEADER);
        if (raw == null || raw.isBlank()) {
            headerName = ACTIVE_TENANT_HEADER;
            raw = request.getHeader(ACTIVE_TENANT_HEADER);
        }
        if (raw == null || raw.isBlank()) {
            return null;
        }
        UUID candidate;
        try {
            candidate = UUID.fromString(raw.trim());
        } catch (IllegalArgumentException e) {
            log.warn("AUDIT: ROOT tenant switcher ignored — malformed {} header value '{}'",
                    headerName, raw);
            return null;
        }
        if (!tenantRepository.existsById(candidate)) {
            log.warn("AUDIT: ROOT tenant switcher ignored — unknown tenant id {} in {} header",
                    candidate, headerName);
            return null;
        }
        log.debug("ROOT tenant switcher active — scoping to tenant {} (via {})",
                candidate, headerName);
        return candidate;
    }

    /**
     * Returns true if the caller is allowed to access rows tagged with
     * {@code targetTenantId}. ROOT may access any tenant; everyone
     * else only their own.
     */
    public boolean canAccessTenant(UUID targetTenantId) {
        if (targetTenantId == null) return false;
        UUID scope = currentScope();
        return scope == null || scope.equals(targetTenantId);
    }

    /**
     * Convenience — true when the caller's CURRENT effective scope is
     * unrestricted (cross-tenant). For a ROOT this is true only when they
     * have NOT selected a tenant via the switcher header. Use
     * {@link #isCrossTenantAdmin()} instead when you need the caller's
     * capability (e.g. "may this caller list every tenant?") independent of the
     * active selection.
     */
    public boolean isUnrestricted() {
        return currentScope() == null;
    }

    /**
     * True iff the caller has the cross-tenant administration CAPABILITY
     * (ROOT), regardless of which tenant they have currently selected via the
     * switcher header.
     *
     * <p>Distinct from {@link #isUnrestricted()}: a ROOT who has selected a
     * tenant is {@code isCrossTenantAdmin() == true} but
     * {@code isUnrestricted() == false}. The tenant-switcher dropdown must use
     * THIS method so the full tenant list stays available after a selection.</p>
     */
    public boolean isCrossTenantAdmin() {
        return rbacService.isRoot();
    }
}
