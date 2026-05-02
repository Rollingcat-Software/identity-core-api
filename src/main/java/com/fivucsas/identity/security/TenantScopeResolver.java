package com.fivucsas.identity.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

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

    private final RbacAuthorizationService rbacService;

    /**
     * Returns {@code null} for SUPER_ADMIN callers ("no scope restriction"),
     * the caller's tenant UUID otherwise, or the fail-closed sentinel when
     * no tenant can be resolved.
     */
    public UUID currentScope() {
        if (rbacService.isSuperAdmin()) {
            return null;
        }
        return rbacService.getCurrentUser()
                .map(u -> u.getTenant() != null ? u.getTenant().getId() : FAIL_CLOSED_EMPTY_SCOPE)
                .orElse(FAIL_CLOSED_EMPTY_SCOPE);
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
