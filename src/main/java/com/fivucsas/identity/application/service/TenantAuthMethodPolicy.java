package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.TenantAuthMethod;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Single source of truth for "is this login method ALLOWED for this tenant?".
 *
 * <p><b>SAFE / FAIL-OPEN semantics (deliberate — this gates dashboard login):</b>
 * a login method is BLOCKED <em>only</em> when there is an EXPLICIT
 * {@link TenantAuthMethod} row with {@code is_enabled=false} for that
 * {@code (tenant, method)} pair. Anything else — no row at all, an
 * {@code is_enabled=true} row, a null tenant, or any lookup error — resolves to
 * ALLOWED. This guarantees a tenant that never configured its Auth-Methods
 * toggles (e.g. Marmara, which has zero {@code tenant_auth_methods} rows) is
 * never locked out: "no row = today's default = allowed".
 *
 * <p>Used by the login-time enforcement gate (so an explicitly-disabled method
 * cannot be used as an MFA step / Layer-1 factor) and by the write-side guards
 * (flow builder + method-disable) so the admin cannot create a state where an
 * active flow requires a disabled method.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TenantAuthMethodPolicy {

    private final TenantAuthMethodRepositoryPort tenantAuthMethodRepository;

    /**
     * @return {@code false} ONLY when an explicit {@code is_enabled=false} row
     *         exists for {@code (tenantId, methodType)}; {@code true} in every
     *         other case (no row, enabled row, null tenant, lookup failure).
     */
    @Transactional(readOnly = true)
    public boolean isLoginMethodAllowedForTenant(UUID tenantId, AuthMethodType methodType) {
        if (tenantId == null || methodType == null) {
            // No tenant context / unknown method ⇒ cannot prove an explicit
            // disable ⇒ fail OPEN (allow). The caller's other gates still apply.
            return true;
        }
        try {
            Optional<TenantAuthMethod> row =
                    tenantAuthMethodRepository.findByTenantIdAndType(tenantId, methodType);
            // Allowed unless an explicit row says is_enabled=false.
            return row.map(TenantAuthMethod::isEnabled).orElse(true);
        } catch (Exception e) {
            // A misconfigured / unavailable lookup must NEVER lock a tenant out:
            // fail OPEN and log loudly so it can be investigated.
            log.warn("isLoginMethodAllowedForTenant lookup failed — tenantId={}, method={}: {} (failing OPEN/allow)",
                    tenantId, methodType, e.getMessage());
            return true;
        }
    }

    /**
     * True iff an explicit {@code is_enabled=false} row exists for the pair —
     * the negation of {@link #isLoginMethodAllowedForTenant}, provided for
     * readability at the write-side guards ("is this method explicitly
     * disabled for the tenant?").
     */
    @Transactional(readOnly = true)
    public boolean isLoginMethodExplicitlyDisabled(UUID tenantId, AuthMethodType methodType) {
        return !isLoginMethodAllowedForTenant(tenantId, methodType);
    }
}
