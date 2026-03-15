package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetPermissionByIdQuery;
import com.fivucsas.identity.application.dto.response.PermissionResponse;
import com.fivucsas.identity.application.port.input.ManagePermissionUseCase;
import com.fivucsas.identity.domain.exception.PermissionNotFoundException;
import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.application.port.output.PermissionRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for permission management (read-only operations).
 *
 * Permissions are created via database migrations and are immutable.
 * This service provides read access to permissions.
 *
 * Implements the ManagePermissionUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManagePermissionService implements ManagePermissionUseCase {

    private final PermissionRepositoryPort permissionRepository;

    @Override
    @Transactional(readOnly = true)
    public PermissionResponse getPermissionById(GetPermissionByIdQuery query) {
        log.info("Fetching permission by id: {}", query.getPermissionId());

        UUID uuid = UUID.fromString(query.getPermissionId());
        Permission permission = permissionRepository.findById(uuid)
                .orElseThrow(() -> new PermissionNotFoundException(query.getPermissionId()));

        return mapToPermissionResponse(permission);
    }

    @Override
    @Transactional(readOnly = true)
    public List<PermissionResponse> getAllPermissions() {
        log.info("Fetching all permissions");

        return permissionRepository.findAllOrdered().stream()
                .map(this::mapToPermissionResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<PermissionResponse> getPermissionsByResource(String resource) {
        log.info("Fetching permissions for resource: {}", resource);

        return permissionRepository.findByResource(resource).stream()
                .map(this::mapToPermissionResponse)
                .collect(Collectors.toList());
    }

    private PermissionResponse mapToPermissionResponse(Permission permission) {
        return PermissionResponse.builder()
                .id(permission.getId().toString())
                .name(permission.getName())
                .description(permission.getDescription())
                .resource(permission.getResource())
                .action(permission.getAction())
                .authority(permission.getAuthorityName())
                .build();
    }
}
