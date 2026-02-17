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
    TenantAuthMethodResponse configureTenantMethod(UUID tenantId, UUID authMethodId, boolean enabled, String config);
}
