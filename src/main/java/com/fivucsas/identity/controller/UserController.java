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
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserSettings;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
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
    private final TenantScopeResolver tenantScopeResolver;
    private final JpaTenantRepository tenantRepository;

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
            .userType(request.getUserType())
            .roleIds(request.getRoleIds())
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
            .userType(request.getUserType())
            .roleIds(request.getRoleIds())
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
    @PreAuthorize("@rbac.isTenantAdmin() or @rbac.hasPermission('guest:invite')")
    public ResponseEntity<GuestInvitationResponse> inviteGuest(
            @Valid @RequestBody InviteGuestRequest request,
            @RequestParam(required = false) UUID tenantId) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        // Resolve target tenant: ROOT MUST pin to a tenant via the
        // `tenantId` query param (no silent fallback to currentUser.tenant /
        // system tenant); tenant-scoped callers always invite into their own
        // tenant. Caller without a resolvable tenant rejects with 400 rather
        // than defaulting into an unintended tenant.
        // Copilot post-merge round 5: previous fallback would silently invite
        // guests into the ROOT's home (often `system`) tenant when the
        // caller forgot `?tenantId=`. Now the request fails fast with 400.
        UUID callerScope = tenantScopeResolver.currentScope();
        Tenant targetTenant;
        if (callerScope == null) {
            // ROOT — must pick a tenant to invite into explicitly
            if (tenantId == null) {
                throw new IllegalArgumentException(
                        "'tenantId' query parameter is required when ROOT invites a guest.");
            }
            targetTenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Tenant not found: " + tenantId));
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            throw new UnauthorizedException();
        } else {
            targetTenant = currentUser.getTenant();
        }

        log.info("POST /api/v1/guests/invite - Inviting guest {} into tenant {} by {}",
                request.getEmail(), targetTenant.getId(), currentUser.getEmail());

        String inviterName = currentUser.getFullName();
        if (inviterName == null || inviterName.isBlank()) {
            inviterName = currentUser.getEmail();
        }

        GuestInvitation invitation = guestLifecycleService.createInvitation(
                targetTenant,
                request.getEmail(),
                currentUser,
                request.getAccessDurationHours(),
                request.getMessage(),
                inviterName,
                request.getLocale()
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

    @PostMapping("/api/v1/guests/{invitationId}/resend")
    @Operation(summary = "Resend a pending guest invitation email")
    @PreAuthorize("@rbac.isTenantAdmin() or @rbac.hasPermission('guest:invite')")
    public ResponseEntity<Void> resendInvitation(@PathVariable UUID invitationId) {
        log.info("POST /api/v1/guests/{}/resend - Resending guest invitation", invitationId);
        guestLifecycleService.resendInvitation(invitationId);
        return ResponseEntity.noContent().build();
    }

    /**
     * #10 — Member-side "My Invitations": the invitations RECEIVED by the
     * currently-authenticated user (matched on their login email), across every
     * tenant. Authenticated-only and intrinsically self-scoped (a caller can
     * only ever see invitations addressed to THEIR OWN email), so it needs no
     * admin/guest permission. Backs the mobile My-Invitations screen, which
     * previously had no listing endpoint and surfaced a JSON-decode error.
     */
    @GetMapping("/api/v1/guests/my-invitations")
    @Operation(summary = "List invitations received by the current user (across tenants)")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<GuestInvitationResponse>> listMyReceivedInvitations() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);

        String email = currentUser.getEmail();
        if (email == null || email.isBlank()) {
            return ResponseEntity.ok(List.of());
        }

        List<GuestInvitation> received =
                invitationRepository.findByEmailIgnoreCaseOrderByCreatedAtDesc(email);

        return ResponseEntity.ok(received.stream()
                .limit(MAX_PLATFORM_WIDE_GUESTS)
                .map(GuestInvitationResponse::from)
                .collect(Collectors.toList()));
    }

    @GetMapping("/api/v1/guests")
    @Operation(summary = "List guest invitations for current tenant (or platform-wide for ROOT)")
    @PreAuthorize("@rbac.isTenantAdmin() or @rbac.hasPermission('guest:read')")
    public ResponseEntity<List<GuestInvitationResponse>> listInvitations(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) UUID tenantId) {

        InvitationStatus statusFilter = (status != null && !status.isEmpty())
                ? InvitationStatus.valueOf(status.toUpperCase(java.util.Locale.ROOT))
                : null;

        UUID callerScope = tenantScopeResolver.currentScope();
        UUID effectiveTenantId;
        if (callerScope == null) {
            // ROOT — `tenantId` query param is optional; null means
            // platform-wide (cross-tenant) listing.
            effectiveTenantId = tenantId;
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            return ResponseEntity.ok(List.of());
        } else {
            // Tenant-scoped caller: ignore any tenantId that isn't theirs.
            effectiveTenantId = callerScope;
        }

        List<GuestInvitation> invitations;
        if (effectiveTenantId == null) {
            // ROOT, no tenant pinned → cross-tenant listing.
            // Copilot post-merge round 5: cross-tenant dumps are bounded by a
            // hard cap (MAX_PLATFORM_WIDE_GUESTS) to prevent runaway memory/
            // latency. Operators who need more should pass a `status` filter
            // or `tenantId`. A paginated endpoint is a planned follow-up.
            invitations = statusFilter != null
                    ? invitationRepository.findAllByStatusOrderByCreatedAtDesc(statusFilter)
                    : invitationRepository.findAllOrderByCreatedAtDesc();
        } else if (statusFilter != null) {
            invitations = invitationRepository.findByTenantIdAndStatus(effectiveTenantId, statusFilter);
        } else {
            invitations = invitationRepository.findByTenantIdOrderByCreatedAtDesc(effectiveTenantId);
        }

        return ResponseEntity.ok(invitations.stream()
                .limit(MAX_PLATFORM_WIDE_GUESTS)
                .map(GuestInvitationResponse::from)
                .collect(Collectors.toList()));
    }

    /** Hard server-side cap on guest-invitation listings (Copilot post-merge round 5). */
    private static final int MAX_PLATFORM_WIDE_GUESTS = 1000;

    @GetMapping("/api/v1/guests/count")
    @Operation(summary = "Count active guests in tenant (or platform-wide for ROOT)")
    @PreAuthorize("@rbac.isTenantAdmin() or @rbac.hasPermission('guest:read')")
    public ResponseEntity<Long> countActiveGuests(
            @RequestParam(required = false) UUID tenantId) {
        UUID callerScope = tenantScopeResolver.currentScope();
        UUID effectiveTenantId;
        if (callerScope == null) {
            effectiveTenantId = tenantId;
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            return ResponseEntity.ok(0L);
        } else {
            effectiveTenantId = callerScope;
        }

        long count = effectiveTenantId == null
                ? invitationRepository.countActiveGuestsPlatformWide(Instant.now())
                : invitationRepository.countActiveGuestsInTenant(effectiveTenantId, Instant.now());

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

    @PostMapping("/api/v1/guests/invitations/{invitationId}/revoke")
    @Operation(summary = "Revoke a PENDING (un-accepted) guest invitation")
    @PreAuthorize("@rbac.isTenantAdmin() or @rbac.hasPermission('guest:revoke')")
    public ResponseEntity<Void> revokePendingInvitation(@PathVariable UUID invitationId) {
        // Acting admin id only (no entity.User load) — respects the hexagonal
        // entity.User boundary ratchet for new controller code.
        UUID actorUserId = rbacService.getCurrentUserId()
                .orElseThrow(() -> new UnauthorizedException());

        // Tenant-scope guard: a scoped caller (TENANT_ADMIN) may only revoke
        // invitations belonging to a tenant they can access. ROOT with
        // no active scope passes for any tenant; with X-Active-Tenant set, the
        // invitation must belong to the selected tenant. 404 (not 403) when the
        // invitation isn't visible to the caller — don't leak existence across
        // tenants.
        GuestInvitation invitation = invitationRepository.findById(invitationId).orElse(null);
        if (invitation == null
                || !tenantScopeResolver.canAccessTenant(invitation.getTenant().getId())) {
            throw new ResourceNotFoundException("Guest invitation not found: " + invitationId);
        }

        log.info("POST /api/v1/guests/invitations/{}/revoke - Revoking pending invitation by actor {}",
                invitationId, actorUserId);

        guestLifecycleService.revokeInvitation(invitationId, actorUserId);

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
