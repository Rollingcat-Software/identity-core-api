package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.entity.TenantAuthMethod;

import java.time.Instant;
import java.util.UUID;

public record TenantAuthMethodResponse(
    UUID id,
    AuthMethodResponse authMethod,
    boolean isEnabled,
    String config,
    Instant createdAt
) {
    public static TenantAuthMethodResponse from(TenantAuthMethod entity) {
        return new TenantAuthMethodResponse(
            entity.getId(),
            AuthMethodResponse.from(entity.getAuthMethod()),
            entity.isEnabled(),
            entity.getConfig(),
            entity.getCreatedAt()
        );
    }
}
