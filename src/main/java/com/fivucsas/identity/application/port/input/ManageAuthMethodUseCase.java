package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.response.AuthMethodResponse;
import com.fivucsas.identity.application.dto.response.TenantAuthMethodResponse;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;

import java.util.List;
import java.util.UUID;

public interface ManageAuthMethodUseCase {
    List<AuthMethodResponse> listAllMethods();
    AuthMethodResponse getMethodByType(AuthMethodType type);
    List<TenantAuthMethodResponse> listTenantMethods(UUID tenantId);

    /**
     * Configure a tenant's auth method.
     *
     * <p>When {@code enabled=false} and the method is referenced by an ACTIVE
     * auth flow for the tenant, the change is REJECTED with
     * {@link com.fivucsas.identity.domain.exception.AuthMethodInUseException}
     * (HTTP 409) unless {@code force=true} — preventing the admin from silently
     * breaking login. {@code force=true} disables anyway (the admin's explicit
     * choice). Enabling ({@code enabled=true}) is never gated.
     */
    TenantAuthMethodResponse configureTenantMethod(UUID tenantId, UUID authMethodId, boolean enabled, String config, boolean force);

    /** Backward-compatible overload — equivalent to {@code force=false}. */
    default TenantAuthMethodResponse configureTenantMethod(UUID tenantId, UUID authMethodId, boolean enabled, String config) {
        return configureTenantMethod(tenantId, authMethodId, enabled, config, false);
    }
}
