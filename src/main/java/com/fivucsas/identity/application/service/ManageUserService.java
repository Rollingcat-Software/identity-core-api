package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuditLogQueryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.TenantNotFoundException;
import com.fivucsas.identity.domain.exception.TenantUserQuotaExceededException;
import com.fivucsas.identity.domain.exception.RoleNotFoundException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.user.*;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.security.TenantScopeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for user management (CRUD operations).
 *
 * Implements the ManageUserUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageUserService implements ManageUserUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final JpaTenantRepository tenantRepository;
    private final RoleRepositoryPort roleRepository;
    private final UserRoleRepositoryPort userRoleRepository;
    private final AuditLogQueryPort auditLogQueryPort;
    private final AuditLogPort auditLogPort;
    private final TenantScopeResolver tenantScopeResolver;

    @Override
    @Transactional
    public UserResponse createUser(CreateUserCommand command) {
        log.info("Creating new user: {}", command.getEmail());

        if (userRepository.existsByEmail(command.getEmail())) {
            throw new DuplicateEmailException(command.getEmail());
        }

        // Validate using value objects
        Email email = Email.of(command.getEmail());
        FullName fullName = FullName.of(command.getFirstName(), command.getLastName());
        HashedPassword hashedPassword = HashedPassword.of(passwordEncoder.encode(command.getPassword()));

        // Handle tenant assignment
        Tenant tenant = null;
        if (command.getTenantId() != null && !command.getTenantId().isEmpty()) {
            UUID tenantUuid = UUID.fromString(command.getTenantId());
            tenant = tenantRepository.findById(tenantUuid)
                .orElseThrow(() -> new TenantNotFoundException(command.getTenantId()));
        }

        // P0-#7 (INVESTIGATION_MASTER_2026-05-07): enforce tenant.max_users on
        // the admin-create path too. RegisterUserService gates the public
        // self-service flow; this gates the ROOT/TENANT_ADMIN admin UI
        // path. Tenant-less users (system-wide) are not capped here.
        if (tenant != null) {
            long currentUserCount = userRepository.countByTenantId(tenant.getId());
            if (currentUserCount >= tenant.getMaxUsers()) {
                log.warn("AUDIT: User creation refused — tenant quota exceeded, tenantId={}, currentUsers={}, maxUsers={}",
                    tenant.getId(), currentUserCount, tenant.getMaxUsers());
                throw new TenantUserQuotaExceededException(tenant.getMaxUsers());
            }
        }

        User user = User.builder()
            .email(email.getValue())
            .passwordHash(hashedPassword.getValue())
            .firstName(fullName.getFirstName())
            .lastName(fullName.getLastName())
            .idNumber(command.getIdNumber())
            .phoneNumber(command.getPhoneNumber())
            .address(command.getAddress())
            .tenant(tenant)
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .build();

        user = userRepository.save(user);
        log.info("User created successfully: {}", user.getId());

        // Handle role assignment
        if (command.getRole() != null && !command.getRole().isEmpty()) {
            try {
                Role role;
                if (tenant != null) {
                    // Look for role within the user's tenant
                    role = roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(tenant.getId(), command.getRole())
                        .orElseThrow(() -> new RoleNotFoundException(command.getRole()));
                } else {
                    // No tenant context — look up globally (only safe for unique system roles)
                    role = roleRepository.findByNameAndDeletedAtIsNull(command.getRole())
                        .orElseThrow(() -> new RoleNotFoundException(command.getRole()));
                }

                // Create user-role assignment
                UserRole userRole = UserRole.create(user, role, null, null);
                userRoleRepository.save(userRole);
                log.info("Role {} assigned to user {} during creation", command.getRole(), user.getId());
            } catch (RoleNotFoundException e) {
                log.warn("Role {} not found for user creation, skipping role assignment", command.getRole());
            }
        }

        UserResponse createdResponse = mapToUserResponse(user);

        // #9 (2026-05-21): admin-create was a silent mutation — no audit row.
        // Mirror the deleteUser() USER_DELETED emission: emit USER_CREATED with
        // the new user's id, the acting tenant scope, and the assigned tenant.
        // IP slot is null because the use-case API is String-only (no request
        // context), matching deleteUser(). The target id is read from the
        // response DTO (not entity.User) to respect the hexagonal-boundary
        // ratchet enforced by UserDomainBoundaryTest.
        UUID createScopeTenantId = resolveTenantScope();
        auditLogPort.logSecurityEvent(
                createdResponse.getId(),
                "USER_CREATED",
                null,
                String.format("Created; actorTenant=%s, targetTenant=%s",
                        createScopeTenantId == null ? "ROOT" : createScopeTenantId.toString(),
                        tenant == null ? "NONE" : tenant.getId().toString())
        );

        return createdResponse;
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(GetUserByIdQuery query) {
        log.info("Fetching user by id: {}", query.getUserId());

        UUID uuid = UUID.fromString(query.getUserId());
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(query.getUserId()));

        // Tenant-scope guard: list endpoints filter by resolveTenantScope(),
        // but the by-id endpoint relied on @PreAuthorize alone, letting a
        // TENANT_ADMIN of tenant A read users in tenant B by direct UUID.
        // Closes audit-edge 2026-04-28 P0 #2. ROOT (null scope) and
        // self-reads (already permitted by @PreAuthorize) bypass.
        enforceTenantScope(user, query.getUserId());

        return enrichWithLoginInfo(mapToUserResponse(user));
    }

    private void enforceTenantScope(User user, String requestedId) {
        UUID scopeTenantId = resolveTenantScope();
        if (scopeTenantId == null) {
            return; // ROOT — cross-tenant reads allowed by design
        }
        if (user.getTenant() == null) {
            log.warn("User {} has no tenant; rejecting cross-tenant access", requestedId);
            throw new UserNotFoundException(requestedId);
        }
        if (!scopeTenantId.equals(user.getTenant().getId())) {
            log.warn("Cross-tenant by-id access refused: caller scope={}, target user tenant={}",
                    scopeTenantId, user.getTenant().getId());
            // 404 not 403 — don't leak existence of users in other tenants
            throw new UserNotFoundException(requestedId);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers(GetAllUsersQuery query) {
        // Tenant admins and below see only their own tenant's users.
        // ROOT sees everything. Callers without a tenant (shouldn't happen
        // for authenticated requests) get empty to fail closed.
        UUID scopeTenantId = resolveTenantScope();
        log.info("Fetching users (page={}, size={}, tenantScope={})",
                query.getPage(), query.getSize(),
                scopeTenantId == null ? "ALL" : scopeTenantId);

        List<User> users = scopeTenantId == null
                ? userRepository.findAll(query.getPage(), query.getSize())
                : userRepository.findAllByTenantId(scopeTenantId, query.getPage(), query.getSize());

        return users.stream()
            .map(this::mapToUserResponse)
            .map(this::enrichWithLoginInfo)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> searchUsers(SearchUsersQuery query) {
        UUID scopeTenantId = resolveTenantScope();
        log.info("Searching users with query: {} (tenantScope={})",
                query.getSearchQuery(), scopeTenantId == null ? "ALL" : scopeTenantId);

        List<User> users = scopeTenantId == null
                ? userRepository.searchUsers(query.getSearchQuery())
                : userRepository.searchUsersByTenant(scopeTenantId, query.getSearchQuery());

        return users.stream()
            .map(this::mapToUserResponse)
            .map(this::enrichWithLoginInfo)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public long countAllUsers() {
        UUID scopeTenantId = resolveTenantScope();
        return scopeTenantId == null
                ? userRepository.count()
                : userRepository.countByTenantId(scopeTenantId);
    }

    /**
     * Returns the tenant the current caller is allowed to enumerate, or
     * {@code null} if the caller is ROOT (no scope restriction).
     *
     * <p>Prevents TENANT_ADMIN and below from listing users in other tenants
     * via {@code /api/v1/users}. The {@code @PreAuthorize("user:read")} check
     * verifies the permission exists, not the tenant scope.</p>
     *
     * <p>Source of truth is the DB lookup in {@link RbacAuthorizationService}.
     * Historically the Spring principal was a plain {@code UserDetails} (not
     * {@code CustomUserDetails}) so {@code AuthorizationService.getCurrentTenantId()}
     * silently returned null and would re-open the leak — fixed in the PR that
     * wires {@code CustomUserDetails} as the authenticated principal. Routing
     * through the DB is kept here to avoid coupling tenant scope to principal
     * cache state.</p>
     *
     * <p>Fail-closed: if the current user cannot be resolved to a tenant,
     * return a zero-UUID sentinel that matches no tenant, so the query
     * produces an empty list rather than an unbounded one.</p>
     */
    private static final UUID FAIL_CLOSED_EMPTY_SCOPE = TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE;

    /**
     * Delegates to the shared {@link TenantScopeResolver} so {@code /users}
     * scopes on the SAME unified {@code X-Tenant-ID} switcher header as every
     * other admin list view. Semantics:
     * <ul>
     *   <li>ROOT + {@code X-Tenant-ID=<t>} → {@code t} (selected tenant).</li>
     *   <li>ROOT + no header → {@code null} (cross-tenant: see all).</li>
     *   <li>TENANT_ADMIN / USER → their home tenant (header ignored).</li>
     *   <li>unresolvable caller → fail-closed sentinel (empty result).</li>
     * </ul>
     *
     * <p>Previously this returned {@code null} for ANY ROOT and leaned on
     * the implicit Hibernate {@code tenantFilter} to do the scoping — making the
     * result silently dependent on filter state and inconsistent with the other
     * controllers. Now the scope is explicit and uniform.</p>
     */
    private UUID resolveTenantScope() {
        return tenantScopeResolver.currentScope();
    }

    @Override
    @Transactional
    public UserResponse updateUser(UpdateUserCommand command) {
        log.info("Updating user: {}", command.getUserId());

        UUID uuid = UUID.fromString(command.getUserId());
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        enforceTenantScope(user, command.getUserId());

        // Use value objects for validation
        if (command.getFirstName() != null && command.getLastName() != null) {
            FullName fullName = FullName.of(command.getFirstName(), command.getLastName());
            user.setFirstName(fullName.getFirstName());
            user.setLastName(fullName.getLastName());
        } else {
            if (command.getFirstName() != null) {
                user.setFirstName(command.getFirstName());
            }
            if (command.getLastName() != null) {
                user.setLastName(command.getLastName());
            }
        }

        if (command.getPhoneNumber() != null) {
            PhoneNumber phone = PhoneNumber.ofNullable(command.getPhoneNumber());
            user.updatePhoneNumber(phone);
        }

        if (command.getAddress() != null) {
            Address address = Address.ofNullable(command.getAddress());
            user.updateAddress(address);
        }

        user = userRepository.save(user);
        log.info("User updated successfully: {}", command.getUserId());

        // #9 (2026-05-21): admin-update was a silent mutation — no audit row.
        // Mirror deleteUser(): emit USER_UPDATED with target id (the command's
        // userId, avoiding entity.User per the hexagonal-boundary ratchet) +
        // actor tenant scope. IP slot null (use-case API is String-only).
        UUID updateScopeTenantId = resolveTenantScope();
        auditLogPort.logSecurityEvent(
                command.getUserId(),
                "USER_UPDATED",
                null,
                String.format("Updated; actorTenant=%s",
                        updateScopeTenantId == null ? "ROOT" : updateScopeTenantId.toString())
        );

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        log.info("Deleting user: {}", userId);

        UUID uuid = UUID.fromString(userId);
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(userId));

        enforceTenantScope(user, userId);

        // Capture actor + tenant context BEFORE the soft-delete write so the
        // audit row reflects who initiated the action and which tenant the
        // target user belonged to. We use the entity.User-free helpers
        // (RbacAuthorizationService.getCurrentUserTenantId,
        // resolveTenantScope) so the hexagonal-boundary ratchet
        // (UserDomainBoundaryTest) does not register new violations.
        // resolveTenantScope() returns null for ROOT — keep that
        // as "ROOT" for log readability.
        UUID scopeTenantId = resolveTenantScope();
        String actorTenantId = scopeTenantId == null
                ? "ROOT"
                : scopeTenantId.toString();

        userRepository.delete(user);
        log.info("User deleted successfully: {}", userId);

        // INVESTIGATION_MASTER_2026-05-07 §"audit-log blind spots":
        // ManageUserService imported only AuditLogReadPort; soft-deletes
        // wrote zero audit rows. Emit USER_DELETED with target userId,
        // actor userId, and tenantId via the existing logSecurityEvent
        // pattern. We don't have a request IP here (the use-case API is
        // String-only), so the IP slot is left null — the actor is the
        // load-bearing "who" attribution.
        auditLogPort.logSecurityEvent(
                userId,
                "USER_DELETED",
                null,
                String.format("Soft-deleted; actorTenant=%s", actorTenantId)
        );
    }

    private UserResponse mapToUserResponse(User user) {
        return com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);
    }

    private UserResponse enrichWithLoginInfo(UserResponse response) {
        // Prefer the audit log because it survives even if `users.last_login_at`
        // is reset by an admin tool, but fall back to the value from the User
        // entity when audit lookup is empty. The audit-log action emitted by
        // AuthenticateUserService is `USER_LOGIN` (see AuditLogAdapter); the
        // previous code queried for the wrong constant `USER_AUTHENTICATED`
        // and so always returned null, displaying "Never" on the Users list
        // for users who had logged in many times.
        Instant auditLastLogin = getLastLoginAt(response.getId());
        String auditLastIp = getLastLoginIp(response.getId());
        return response.toBuilder()
            .lastLoginAt(auditLastLogin != null ? auditLastLogin : response.getLastLoginAt())
            .lastLoginIp(auditLastIp != null ? auditLastIp : response.getLastLoginIp())
            .build();
    }

    private Instant getLastLoginAt(String userId) {
        try {
            var page = auditLogQueryPort.findByUserIdAndActionOrderByCreatedAtDesc(
                    UUID.fromString(userId), "USER_LOGIN",
                    PageRequest.of(0, 1));
            return page.hasContent() ? page.getContent().getFirst().getCreatedAt() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String getLastLoginIp(String userId) {
        try {
            var page = auditLogQueryPort.findByUserIdAndActionOrderByCreatedAtDesc(
                    UUID.fromString(userId), "USER_LOGIN",
                    PageRequest.of(0, 1));
            return page.hasContent() ? page.getContent().getFirst().getIpAddress() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
