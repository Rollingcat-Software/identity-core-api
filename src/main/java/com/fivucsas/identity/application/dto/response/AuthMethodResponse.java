package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;

import java.util.List;
import java.util.UUID;

public record AuthMethodResponse(
    UUID id,
    AuthMethodType type,
    String name,
    String description,
    AuthMethodCategory category,
    List<String> platforms,
    boolean requiresEnrollment,
    boolean isActive
) {
    public static AuthMethodResponse from(AuthMethod entity) {
        return new AuthMethodResponse(
            entity.getId(),
            entity.getType(),
            entity.getName(),
            entity.getDescription(),
            entity.getCategory(),
            entity.getPlatforms(),
            entity.isRequiresEnrollment(),
            entity.isActive()
        );
    }
}
