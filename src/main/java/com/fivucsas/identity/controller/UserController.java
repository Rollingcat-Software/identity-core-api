package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.ChangePasswordCommand;
import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.ChangePasswordUseCase;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.application.port.output.UserSettingsRepositoryPort;
import com.fivucsas.identity.application.service.GuestLifecycleService;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.dto.AcceptInvitationRequest;
import com.fivucsas.identity.dto.ChangePasswordRequest;
import com.fivucsas.identity.dto.CreateUserRequest;
import com.fivucsas.identity.dto.ExtendGuestAccessRequest;
import com.fivucsas.identity.dto.GuestInvitationResponse;
import com.fivucsas.identity.dto.InviteGuestRequest;
import com.fivucsas.identity.dto.UpdateUserRequest;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.InvitationStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserSettings;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST controller for user management endpoints.
 *
 * Merges: UserController + UserSettingsController + GuestController
 */
@RestController
@RequiredArgsConstructor
@Validated
@Slf4j
@Tag(name = "User Management", description = "User CRUD, settings and guest management operations")
public class UserController {

    private static final Map<String, Object> DEFAULT_SETTINGS = Map.of(
            "notifications", Map.of(
                    "email", true,
                    "push", true,
                    "securityAlerts", true
            ),
            "security", Map.of(
                    "twoFactorEnabled", false,
                    "sessionTimeout", 30
            ),
            "appearance", Map.of(
                    "theme", "light",
                    "language", "en",
                    "density", "comfortable"
            )
    );

    private final ManageUserUseCase manageUserUseCase;
    private final ChangePasswordUseCase changePasswordUseCase;
    private final UserSettingsRepositoryPort userSettingsRepository;
    private final GuestLifecycleService guestLifecycleService;
    private final GuestInvitationRepositoryPort invitationRepository;
    private final RbacAuthorizationService rbacService;

    // --- User CRUD endpoints ---

    @GetMapping("/api/v1/users")
    @Operation(summary = "Get all users")
    @PreAuthorize("@rbac.hasPermission('user:read')")
    public ResponseEntity<Map<String, Object>> getAllUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        log.info("GET /api/v1/users - Get all users (page={}, size={})", page, size);

        GetAllUsersQuery query = GetAllUsersQuery.builder()
            .page(page)
            .size(size)
            .build();

        List<UserResponse> pagedUsers = manageUserUseCase.getAllUsers(query);
        long totalElements = manageUserUseCase.countAllUsers();
        int totalPages = (int) Math.ceil((double) totalElements / size);

        Map<String, Object> response = new HashMap<>();
        response.put("content", pagedUsers);
        response.put("totalElements", totalElements);
        response.put("totalPages", totalPages);
        response.put("page", page);
        response.put("size", size);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/v1/users/{id}")
    @Operation(summary = "Get user by ID")
    @PreAuthorize("@rbac.hasPermission('user:read') or @userSecurityService.isCurrentUser(#id)")
    public ResponseEntity<UserResponse> getUserById(@PathVariable String id) {
        log.info("GET /api/v1/users/{} - Get user by ID", id);

        GetUserByIdQuery query = GetUserByIdQuery.builder()
            .userId(id)
            .build();

        return ResponseEntity.ok(manageUserUseCase.getUserById(query));
    }

    @PostMapping("/api/v1/users")
    @Operation(summary = "Create new user")
    @PreAuthorize("@rbac.hasPermission('user:create')")
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody CreateUserRequest request) {
        log.info("POST /api/v1/users - Create user: {}", request.getEmail());

        CreateUserCommand command = CreateUserCommand.builder()
            .email(request.getEmail())
            .password(request.getPassword())
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .phoneNumber(request.getPhoneNumber())
            .address(request.getAddress())
            .idNumber(request.getIdNumber())
            .role(request.getRole())
            .tenantId(request.getTenantId())
            .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(manageUserUseCase.createUser(command));
    }

    @PutMapping("/api/v1/users/{id}")
    @Operation(summary = "Update user")
    @PreAuthorize("@rbac.hasPermission('user:update') or @userSecurityService.isCurrentUser(#id)")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable String id,
            @Valid @RequestBody UpdateUserRequest request) {
        log.info("PUT /api/v1/users/{} - Update user", id);

        UpdateUserCommand command = UpdateUserCommand.builder()
            .userId(id)
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .phoneNumber(request.getPhoneNumber())
            .address(request.getAddress())
            .build();

        return ResponseEntity.ok(manageUserUseCase.updateUser(command));
    }

    @DeleteMapping("/api/v1/users/{id}")
    @Operation(summary = "Delete user")
    @PreAuthorize("@rbac.hasPermission('user:delete')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        log.info("DELETE /api/v1/users/{} - Delete user", id);
        manageUserUseCase.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/users/{id}/change-password")
    @Operation(summary = "Change user password")
    @PreAuthorize("hasAuthority('user:update') or @userSecurityService.isCurrentUser(#id)")
    public ResponseEntity<Void> changePassword(
            @PathVariable String id,
            @Valid @RequestBody ChangePasswordRequest request) {
        log.info("POST /api/v1/users/{}/change-password", id);

        changePasswordUseCase.execute(ChangePasswordCommand.builder()
                .userId(id)
                .currentPassword(request.getCurrentPassword())
                .newPassword(request.getNewPassword())
                .build());

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/v1/users/search")
    @Operation(summary = "Search users")
    @PreAuthorize("@rbac.hasPermission('user:read')")
    public ResponseEntity<List<UserResponse>> searchUsers(@RequestParam String query) {
        log.info("GET /api/v1/users/search?query={} - Search users", query);

        SearchUsersQuery searchQuery = SearchUsersQuery.builder()
            .searchQuery(query)
            .build();

        return ResponseEntity.ok(manageUserUseCase.searchUsers(searchQuery));
    }

    // --- User Settings endpoints (merged from UserSettingsController) ---

    @GetMapping("/api/v1/users/{userId}/settings")
    @Operation(summary = "Get user settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> getUserSettings(@PathVariable String userId) {
        log.info("GET /api/v1/users/{}/settings", userId);

        UUID uuid = UUID.fromString(userId);
        return userSettingsRepository.findByUserId(uuid)
                .map(settings -> ResponseEntity.ok(settings.getSettings()))
                .orElseGet(() -> ResponseEntity.ok(new HashMap<>(DEFAULT_SETTINGS)));
    }

    @PutMapping("/api/v1/users/{userId}/settings")
    @Operation(summary = "Update user settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'write') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> updateUserSettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> newSettings) {
        log.info("PUT /api/v1/users/{}/settings", userId);

        UUID uuid = UUID.fromString(userId);
        UserSettings settings = userSettingsRepository.findByUserId(uuid)
                .orElseGet(() -> UserSettings.builder()
                        .userId(uuid)
                        .settings(new HashMap<>(DEFAULT_SETTINGS))
                        .build());

        Map<String, Object> merged = new HashMap<>(settings.getSettings());
        merged.putAll(newSettings);
        settings.setSettings(merged);
        userSettingsRepository.save(settings);

        return ResponseEntity.ok(settings.getSettings());
    }

    @GetMapping("/api/v1/users/{userId}/settings/notifications")
    @Operation(summary = "Get notification settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Object> getNotificationSettings(@PathVariable String userId) {
        return getSettingsSection(userId, "notifications");
    }

    @PutMapping("/api/v1/users/{userId}/settings/notifications")
    @Operation(summary = "Update notification settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'write') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Object> updateNotificationSettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> notificationSettings) {
        return updateSettingsSection(userId, "notifications", notificationSettings);
    }

    @GetMapping("/api/v1/users/{userId}/settings/security")
    @Operation(summary = "Get security settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Object> getSecuritySettings(@PathVariable String userId) {
        return getSettingsSection(userId, "security");
    }

    @PutMapping("/api/v1/users/{userId}/settings/security")
    @Operation(summary = "Update security settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'write') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Object> updateSecuritySettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> securitySettings) {
        return updateSettingsSection(userId, "security", securitySettings);
    }

    @GetMapping("/api/v1/users/{userId}/settings/appearance")
    @Operation(summary = "Get appearance settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Object> getAppearanceSettings(@PathVariable String userId) {
        return getSettingsSection(userId, "appearance");
    }

    @PutMapping("/api/v1/users/{userId}/settings/appearance")
    @Operation(summary = "Update appearance settings")
    @PreAuthorize("hasPermission(#userId, 'user_settings', 'write') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Object> updateAppearanceSettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> appearanceSettings) {
        return updateSettingsSection(userId, "appearance", appearanceSettings);
    }

    // --- Guest endpoints (merged from GuestController) ---

    @PostMapping("/api/v1/guests/invite")
    @Operation(summary = "Invite a guest user")
    @PreAuthorize("@rbac.hasPermission('guest:invite')")
    public ResponseEntity<GuestInvitationResponse> inviteGuest(
            @Valid @RequestBody InviteGuestRequest request) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("POST /api/v1/guests/invite - Inviting guest {} by {}",
                request.getEmail(), currentUser.getEmail());

        GuestInvitation invitation = guestLifecycleService.createInvitation(
                currentUser.getTenant(),
                request.getEmail(),
                currentUser,
                request.getAccessDurationHours(),
                request.getMessage()
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(GuestInvitationResponse.from(invitation));
    }

    @PostMapping("/api/v1/guests/accept")
    @Operation(summary = "Accept a guest invitation")
    public ResponseEntity<Void> acceptInvitation(
            @Valid @RequestBody AcceptInvitationRequest request) {

        log.info("POST /api/v1/guests/accept - Accepting invitation");

        guestLifecycleService.acceptInvitation(
                request.getToken(),
                request.getFirstName(),
                request.getLastName(),
                request.getPassword()
        );

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/api/v1/guests")
    @Operation(summary = "List guest invitations for current tenant")
    @PreAuthorize("@rbac.hasPermission('guest:read')")
    public ResponseEntity<List<GuestInvitationResponse>> listInvitations(
            @RequestParam(required = false) String status) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        UUID tenantId = currentUser.getTenant().getId();

        List<GuestInvitation> invitations;
        if (status != null && !status.isEmpty()) {
            invitations = invitationRepository.findByTenantIdAndStatus(
                    tenantId,
                    InvitationStatus.valueOf(status.toUpperCase(java.util.Locale.ROOT))
            );
        } else {
            invitations = invitationRepository.findByTenantIdOrderByCreatedAtDesc(tenantId);
        }

        return ResponseEntity.ok(invitations.stream()
                .map(GuestInvitationResponse::from)
                .collect(Collectors.toList()));
    }

    @GetMapping("/api/v1/guests/count")
    @Operation(summary = "Count active guests in tenant")
    @PreAuthorize("@rbac.hasPermission('guest:read')")
    public ResponseEntity<Long> countActiveGuests() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        long count = invitationRepository.countActiveGuestsInTenant(
                currentUser.getTenant().getId(), Instant.now());

        return ResponseEntity.ok(count);
    }

    @PostMapping("/api/v1/guests/{guestUserId}/revoke")
    @Operation(summary = "Revoke guest access")
    @PreAuthorize("@rbac.hasPermission('guest:revoke')")
    public ResponseEntity<Void> revokeGuestAccess(@PathVariable UUID guestUserId) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("POST /api/v1/guests/{}/revoke - Revoking access by {}",
                guestUserId, currentUser.getEmail());

        guestLifecycleService.revokeGuestAccess(guestUserId, currentUser);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/guests/{guestUserId}/extend")
    @Operation(summary = "Extend guest access duration")
    @PreAuthorize("@rbac.hasPermission('guest:extend')")
    public ResponseEntity<Void> extendGuestAccess(
            @PathVariable UUID guestUserId,
            @Valid @RequestBody ExtendGuestAccessRequest request) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("POST /api/v1/guests/{}/extend - Extending access by {} hours by {}",
                guestUserId, request.getAdditionalHours(), currentUser.getEmail());

        guestLifecycleService.extendGuestAccess(guestUserId, request.getAdditionalHours(), currentUser);

        return ResponseEntity.noContent().build();
    }

    // --- Private helpers ---

    private ResponseEntity<Object> getSettingsSection(String userId, String section) {
        UUID uuid = UUID.fromString(userId);
        Map<String, Object> allSettings = userSettingsRepository.findByUserId(uuid)
                .map(UserSettings::getSettings)
                .orElse(DEFAULT_SETTINGS);

        Object sectionSettings = allSettings.getOrDefault(section, DEFAULT_SETTINGS.get(section));
        return ResponseEntity.ok(sectionSettings);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> updateSettingsSection(String userId, String section, Map<String, Object> sectionSettings) {
        UUID uuid = UUID.fromString(userId);
        UserSettings settings = userSettingsRepository.findByUserId(uuid)
                .orElseGet(() -> UserSettings.builder()
                        .userId(uuid)
                        .settings(new HashMap<>(DEFAULT_SETTINGS))
                        .build());

        Map<String, Object> allSettings = new HashMap<>(settings.getSettings());
        allSettings.put(section, sectionSettings);
        settings.setSettings(allSettings);
        userSettingsRepository.save(settings);

        return ResponseEntity.ok(sectionSettings);
    }
}
