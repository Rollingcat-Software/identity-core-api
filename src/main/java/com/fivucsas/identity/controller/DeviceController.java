package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.application.service.UsernamelessLoginFlowService;
import com.fivucsas.identity.application.service.WebAuthnCredentialService;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.mapper.UserResponseMapper;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnUserHandle;
import com.fivucsas.identity.security.TenantScopeResolver;
import com.fivucsas.identity.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for device and WebAuthn management.
 *
 * Merges: DeviceController + WebAuthnController
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Devices", description = "Device and WebAuthn/FIDO2 credential management")
public class DeviceController {

    private final ManageDeviceUseCase manageDeviceUseCase;
    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepositoryPort credentialRepository;
    private final WebAuthnCredentialService webAuthnCredentialService;
    private final UserRepository userRepository;
    private final TenantScopeResolver tenantScopeResolver;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final UsernamelessLoginFlowService usernamelessLoginFlowService;

    // --- /api/v1/devices endpoints ---

    @GetMapping("/api/v1/devices")
    @PreAuthorize("@rbac.isTenantAdmin() or hasAuthority('device:read')")
    public ResponseEntity<List<DeviceResponse>> getDevices(
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) UUID tenantId) {
        // Determine the scope to enforce:
        //   - ROOT → callerScope=null → no restriction.
        //   - TENANT_ADMIN / below → callerScope=caller's tenant id.
        // If the caller asks for a tenantId different from their own scope we
        // coerce to the caller's scope (fail-closed), so the dashboard can
        // omit the tenantId param and still get a sensible tenant-scoped
        // list instead of 403.
        UUID callerScope = tenantScopeResolver.currentScope();

        if (userId != null) {
            return ResponseEntity.ok(manageDeviceUseCase.listUserDevices(userId));
        }
        UUID effectiveTenantId;
        if (callerScope == null) {
            // ROOT: tenantId optional. When omitted we list every
            // device on the platform — without this, the admin dashboard
            // can never observe activity from non-system tenants.
            effectiveTenantId = tenantId;
        } else {
            // Tenant-scoped caller: ignore any tenantId that isn't theirs.
            effectiveTenantId = callerScope;
        }
        if (effectiveTenantId == null) {
            return ResponseEntity.ok(manageDeviceUseCase.listAllDevices());
        }
        if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(effectiveTenantId)) {
            return ResponseEntity.ok(List.of());
        }
        return ResponseEntity.ok(manageDeviceUseCase.listTenantDevices(effectiveTenantId));
    }

    @PostMapping("/api/v1/devices")
    @PreAuthorize("hasPermission(null, 'Device', 'device:register') and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<DeviceResponse> registerDevice(
            @RequestParam UUID userId,
            @RequestParam UUID tenantId,
            @Valid @RequestBody RegisterDeviceCommand command) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(manageDeviceUseCase.registerDevice(userId, tenantId, command));
    }

    @DeleteMapping("/api/v1/devices/{deviceId}")
    @PreAuthorize("hasPermission(null, 'Device', 'device:delete')")
    public ResponseEntity<Void> removeDevice(@PathVariable UUID deviceId) {
        manageDeviceUseCase.removeDevice(deviceId);
        return ResponseEntity.noContent().build();
    }

    // --- /api/v1/webauthn endpoints (merged from WebAuthnController) ---

    @PostMapping("/api/v1/webauthn/register/options/{userId}")
    @Operation(summary = "Generate WebAuthn registration options (challenge) for credential creation")
    @PreAuthorize("hasAuthority('webauthn:register') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> getRegistrationOptions(@PathVariable UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        UUID sessionId = UUID.randomUUID();
        String challenge = webAuthnService.generateChallenge(sessionId);

        List<String> existingCredentialIds = credentialRepository.findAllByUserId(userId).stream()
                .map(WebAuthnCredential::getCredentialId)
                .toList();

        return ResponseEntity.ok(Map.of(
                "sessionId", sessionId.toString(),
                "challenge", challenge,
                "rpId", webAuthnService.getRpId(),
                "rpName", "Fivucsas Identity",
                "userId", userId.toString(),
                "userName", user.getEmail(),
                "excludeCredentials", existingCredentialIds,
                "attestation", "direct",
                "authenticatorSelection", Map.of(
                        "authenticatorAttachment", "platform",
                        "requireResidentKey", false,
                        "userVerification", "preferred"
                )
        ));
    }

    @PostMapping("/api/v1/webauthn/register/verify")
    @Operation(summary = "Verify WebAuthn registration (attestation) and store credential")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> verifyRegistration(@RequestBody Map<String, Object> request) {
        UUID userId = UUID.fromString((String) request.get("userId"));
        UUID sessionId = UUID.fromString((String) request.get("sessionId"));
        String credentialId = (String) request.get("credentialId");
        String publicKey = (String) request.get("publicKey");
        String publicKeyAlgorithm = (String) request.getOrDefault("publicKeyAlgorithm", "ES256");
        String attestationFormat = (String) request.get("attestationFormat");
        String transports = (String) request.get("transports");
        String deviceName = (String) request.get("deviceName");
        String clientDataJson = (String) request.get("clientDataJSON");

        if (credentialId == null || credentialId.isEmpty() || publicKey == null || publicKey.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "credentialId and publicKey are required"
            ));
        }

        boolean challengeValid = webAuthnService.validateRegistrationChallenge(sessionId, clientDataJson);
        if (!challengeValid) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid or expired registration challenge"
            ));
        }

        if (credentialRepository.existsByCredentialId(credentialId)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "message", "Credential already registered"
            ));
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        WebAuthnCredential credential = WebAuthnCredential.builder()
                .user(user)
                .credentialId(credentialId)
                .publicKey(publicKey)
                .publicKeyAlgorithm(publicKeyAlgorithm)
                .attestationFormat(attestationFormat)
                .transports(transports)
                .deviceName(deviceName)
                .build();

        webAuthnCredentialService.saveCredential(credential);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "success", true,
                "message", "Credential registered successfully",
                "credentialId", credentialId
        ));
    }

    @GetMapping("/api/v1/webauthn/credentials/{userId}")
    @Operation(summary = "List all WebAuthn credentials for a user")
    @PreAuthorize("hasAuthority('webauthn:read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<List<Map<String, Object>>> listCredentials(@PathVariable UUID userId) {
        List<Map<String, Object>> credentials = credentialRepository.findAllByUserId(userId).stream()
                .map(c -> {
                    var map = new java.util.LinkedHashMap<String, Object>();
                    map.put("id", c.getId().toString());
                    map.put("credentialId", c.getCredentialId());
                    map.put("deviceName", c.getDeviceName() != null ? c.getDeviceName() : "Unknown device");
                    map.put("transports", c.getTransports() != null ? c.getTransports() : "");
                    map.put("createdAt", c.getCreatedAt().toString());
                    map.put("lastUsedAt", c.getLastUsedAt() != null ? c.getLastUsedAt().toString() : "Never");
                    return (Map<String, Object>) map;
                })
                .toList();

        return ResponseEntity.ok(credentials);
    }

    @DeleteMapping("/api/v1/webauthn/credentials/by-id/{id}")
    @Operation(summary = "Delete a WebAuthn credential by database ID")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> deleteCredentialById(@PathVariable UUID id) {
        webAuthnCredentialService.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/api/v1/webauthn/credentials/{credentialId}")
    @Operation(summary = "Delete a WebAuthn credential")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> deleteCredential(@PathVariable String credentialId) {
        webAuthnCredentialService.deleteByCredentialId(credentialId);
        return ResponseEntity.noContent().build();
    }

    // --- Standalone WebAuthn registration/authentication endpoints ---
    // These follow the standard WebAuthn ceremony flow for frontend navigator.credentials API

    @PostMapping("/api/v1/webauthn/register-options")
    @Operation(summary = "Generate WebAuthn registration options for the currently authenticated user")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> registerOptions(@RequestBody(required = false) Map<String, Object> body) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = auth.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException(email));

        UUID sessionId = UUID.randomUUID();
        String challenge = webAuthnService.generateChallenge(sessionId);

        List<String> existingCredentialIds = credentialRepository.findAllByUserId(user.getId()).stream()
                .map(WebAuthnCredential::getCredentialId)
                .toList();

        String deviceName = body != null ? (String) body.get("deviceName") : null;

        // Phase 1: derive the WebAuthn user handle from the user id so the
        // browser sets PublicKeyCredentialUserEntity.id to it. On a later
        // usernameless assertion the authenticator echoes this handle and we
        // resolve the user from it without an up-front email.
        String userHandle = WebAuthnUserHandle.encode(user.getId());

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("sessionId", sessionId.toString());
        options.put("challenge", challenge);
        options.put("rpId", webAuthnService.getRpId());
        options.put("rpName", "Fivucsas Identity");
        options.put("userId", user.getId().toString());
        // The base64url user handle the client MUST use as user.id so the
        // resulting passkey is resolvable usernameless.
        options.put("userHandle", userHandle);
        options.put("userName", user.getEmail());
        options.put("userDisplayName", user.getFirstName() + " " + user.getLastName());
        options.put("excludeCredentials", existingCredentialIds);
        options.put("attestation", "direct");
        // Phase 1: residentKey="required" (requireResidentKey=true) +
        // userVerification="required" make the platform create a DISCOVERABLE
        // passkey that supports usernameless login.
        options.put("authenticatorSelection", Map.of(
                "residentKey", "required",
                "requireResidentKey", true,
                "userVerification", "required"
        ));
        options.put("timeout", 60000);
        if (deviceName != null) {
            options.put("deviceName", deviceName);
        }

        log.info("WebAuthn registration options generated for user: {}", user.getEmail());
        return ResponseEntity.ok(options);
    }

    @PostMapping("/api/v1/webauthn/register")
    @Operation(summary = "Complete WebAuthn registration: validate attestation and store credential")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = auth.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException(email));

        UUID sessionId = UUID.fromString((String) request.get("sessionId"));
        String credentialId = (String) request.get("credentialId");
        String publicKey = (String) request.get("publicKey");
        String publicKeyAlgorithm = (String) request.getOrDefault("publicKeyAlgorithm", "ES256");
        String attestationFormat = (String) request.get("attestationFormat");
        String transports = (String) request.get("transports");
        String deviceName = (String) request.get("deviceName");
        String clientDataJson = (String) request.get("clientDataJSON");

        if (credentialId == null || credentialId.isEmpty() || publicKey == null || publicKey.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "credentialId and publicKey are required"
            ));
        }

        boolean challengeValid = webAuthnService.validateRegistrationChallenge(sessionId, clientDataJson);
        if (!challengeValid) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid or expired registration challenge"
            ));
        }

        if (credentialRepository.existsByCredentialId(credentialId)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "message", "Credential already registered"
            ));
        }

        // Phase 1: passkeys created via register-options are discoverable
        // (residentKey="required"). Honour an explicit client-reported flag if
        // present (e.g. a roaming key that declined resident storage), but
        // default to true for this resident-key ceremony. The user handle is
        // always derived from the authenticated user so usernameless assertion
        // can resolve back to them.
        boolean discoverable = !Boolean.FALSE.equals(request.get("discoverable"));
        String userHandle = WebAuthnUserHandle.encode(user.getId());

        WebAuthnCredential credential = WebAuthnCredential.builder()
                .user(user)
                .credentialId(credentialId)
                .publicKey(publicKey)
                .publicKeyAlgorithm(publicKeyAlgorithm)
                .attestationFormat(attestationFormat)
                .transports(transports)
                .deviceName(deviceName)
                .discoverable(discoverable)
                .userHandle(userHandle)
                .build();

        WebAuthnCredential saved = webAuthnCredentialService.saveCredential(credential);

        log.info("WebAuthn credential registered for user: {}, credentialId: {}, discoverable: {}",
                user.getEmail(), credentialId, discoverable);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "success", true,
                "message", "Credential registered successfully",
                "credentialId", credentialId,
                "id", saved.getId().toString()
        ));
    }

    @PostMapping("/api/v1/webauthn/authenticate-options")
    @Operation(summary = "Generate WebAuthn authentication options (challenge) for navigator.credentials.get()")
    public ResponseEntity<Map<String, Object>> authenticateOptions(@RequestBody Map<String, Object> request) {
        String email = (String) request.get("email");
        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "email is required"
            ));
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            // Return generic error to avoid user enumeration
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "No WebAuthn credentials available"
            ));
        }

        List<WebAuthnCredential> credentials = credentialRepository.findAllByUserId(user.getId());
        if (credentials.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "No WebAuthn credentials available"
            ));
        }

        UUID sessionId = UUID.randomUUID();
        String challenge = webAuthnService.generateChallenge(sessionId);

        List<Map<String, Object>> allowCredentials = credentials.stream()
                .map(c -> {
                    Map<String, Object> cred = new LinkedHashMap<>();
                    cred.put("id", c.getCredentialId());
                    cred.put("type", "public-key");
                    if (c.getTransports() != null && !c.getTransports().isEmpty()) {
                        cred.put("transports", List.of(c.getTransports().split(",")));
                    }
                    return cred;
                })
                .toList();

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("sessionId", sessionId.toString());
        options.put("challenge", challenge);
        options.put("rpId", webAuthnService.getRpId());
        options.put("allowCredentials", allowCredentials);
        options.put("userVerification", "preferred");
        options.put("timeout", 60000);

        log.info("WebAuthn authenticate options generated for email: {}, {} credential(s)", email, credentials.size());
        return ResponseEntity.ok(options);
    }

    @PostMapping("/api/v1/webauthn/authenticate")
    @Operation(summary = "Verify WebAuthn authentication assertion from navigator.credentials.get()")
    public ResponseEntity<Map<String, Object>> authenticate(@RequestBody Map<String, Object> request) {
        String sessionIdStr = (String) request.get("sessionId");
        String credentialId = (String) request.get("credentialId");
        String authenticatorData = (String) request.get("authenticatorData");
        String clientDataJson = (String) request.get("clientDataJSON");
        String signature = (String) request.get("signature");

        if (sessionIdStr == null || credentialId == null || authenticatorData == null
                || clientDataJson == null || signature == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "sessionId, credentialId, authenticatorData, clientDataJSON, and signature are required"
            ));
        }

        UUID sessionId;
        try {
            sessionId = UUID.fromString(sessionIdStr);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid sessionId format"
            ));
        }

        // Look up the stored credential
        WebAuthnCredential credential = credentialRepository.findByCredentialId(credentialId).orElse(null);
        if (credential == null) {
            log.warn("WebAuthn authenticate: credential not found: {}", credentialId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authentication failed"
            ));
        }

        // Verify the assertion cryptographically
        boolean valid = webAuthnService.verifyAssertion(
                sessionId, credentialId, authenticatorData, clientDataJson,
                signature, credential.getPublicKey());

        if (!valid) {
            log.warn("WebAuthn authenticate: assertion verification failed for credential: {}", credentialId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authentication failed"
            ));
        }

        // P1-4: validate the WebAuthn sign-counter per spec §6.1 step 17.
        long newSignCount = webAuthnService.extractSignCount(authenticatorData);
        if (!webAuthnService.validateSignCount(newSignCount, credential.getSignCount())) {
            log.warn("WebAuthn authenticate: sign-counter regression for credential: {} — rejecting (possible cloned credential)",
                    credentialId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authenticator counter regression — possible cloned credential"
            ));
        }
        webAuthnCredentialService.updateSignCount(credential, newSignCount);

        User user = credential.getUser();
        log.info("WebAuthn authentication successful for user: {}, credential: {}", user.getEmail(), credentialId);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "Authentication successful");
        result.put("userId", user.getId().toString());
        result.put("email", user.getEmail());
        result.put("credentialId", credentialId);

        return ResponseEntity.ok(result);
    }

    // --- Phase 1: usernameless / discoverable passkey login ---

    /**
     * Begin a usernameless WebAuthn assertion. No email is supplied: because
     * the registered passkeys are discoverable (resident keys), we return an
     * EMPTY {@code allowCredentials} so the platform offers every passkey the
     * authenticator holds for this RP. The browser calls
     * {@code navigator.credentials.get()} with these options, the user picks a
     * passkey, and the authenticator returns the {@code userHandle} we resolve
     * the account from in {@link #passkeyAuthenticate}.
     */
    @PostMapping("/api/v1/webauthn/passkey/authenticate-options")
    @Operation(summary = "Begin usernameless (discoverable) passkey assertion — no email required")
    public ResponseEntity<Map<String, Object>> passkeyAuthenticateOptions(
            @RequestBody(required = false) Map<String, Object> request) {
        UUID sessionId = UUID.randomUUID();
        String challenge = webAuthnService.generateChallenge(sessionId);

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("sessionId", sessionId.toString());
        options.put("challenge", challenge);
        options.put("rpId", webAuthnService.getRpId());
        // Empty allowCredentials = discoverable: let the authenticator surface
        // any resident passkey for this RP without an up-front credential hint.
        options.put("allowCredentials", List.of());
        options.put("userVerification", "required");
        options.put("timeout", 60000);

        log.info("WebAuthn passkey (usernameless) authenticate options generated, session={}", sessionId);
        return ResponseEntity.ok(options);
    }

    /**
     * Complete a usernameless WebAuthn assertion and mint a session.
     *
     * <p>The account is resolved from the {@code userHandle} the authenticator
     * returned (NOT from an email). We then run the same cryptographic
     * verification + sign-counter check as {@link #authenticate}, and on
     * success mint an access token + refresh token exactly like a completed
     * single-factor login (see {@code AuthenticateUserService}), returning the
     * same {@link AuthenticationResponse} shape.</p>
     */
    @PostMapping("/api/v1/webauthn/passkey/authenticate")
    @Operation(summary = "Complete usernameless passkey assertion and mint a login session")
    public ResponseEntity<?> passkeyAuthenticate(@RequestBody Map<String, Object> request,
                                                 HttpServletRequest httpRequest) {
        String sessionIdStr = (String) request.get("sessionId");
        String credentialId = (String) request.get("credentialId");
        String authenticatorData = (String) request.get("authenticatorData");
        String clientDataJson = (String) request.get("clientDataJSON");
        String signature = (String) request.get("signature");
        String userHandle = (String) request.get("userHandle");

        if (sessionIdStr == null || credentialId == null || authenticatorData == null
                || clientDataJson == null || signature == null || userHandle == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "sessionId, credentialId, authenticatorData, clientDataJSON, "
                            + "signature, and userHandle are required"
            ));
        }

        UUID sessionId;
        try {
            sessionId = UUID.fromString(sessionIdStr);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid sessionId format"
            ));
        }

        // Resolve the user from the user handle the authenticator returned.
        // The handle is the base64url-encoded user-id bytes; decode it, then
        // confirm the presented credential actually belongs to that user (so a
        // forged handle paired with someone else's credentialId can't slip
        // through before signature verification).
        UUID resolvedUserId = WebAuthnUserHandle.decodeToUserId(userHandle);
        if (resolvedUserId == null) {
            log.warn("WebAuthn passkey authenticate: unresolvable userHandle");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authentication failed"
            ));
        }

        WebAuthnCredential credential = credentialRepository.findByCredentialId(credentialId).orElse(null);
        if (credential == null || credential.getUser() == null
                || !resolvedUserId.equals(credential.getUser().getId())) {
            log.warn("WebAuthn passkey authenticate: credential/handle mismatch for credentialId={}", credentialId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authentication failed"
            ));
        }

        // Same cryptographic verification + challenge consumption as the
        // email-scoped path.
        boolean valid = webAuthnService.verifyAssertion(
                sessionId, credentialId, authenticatorData, clientDataJson,
                signature, credential.getPublicKey());
        if (!valid) {
            log.warn("WebAuthn passkey authenticate: assertion verification failed for credentialId={}", credentialId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authentication failed"
            ));
        }

        // WebAuthn §6.1 step 17 sign-counter check (clone detection).
        long newSignCount = webAuthnService.extractSignCount(authenticatorData);
        if (!webAuthnService.validateSignCount(newSignCount, credential.getSignCount())) {
            log.warn("WebAuthn passkey authenticate: sign-counter regression for credentialId={} — possible clone",
                    credentialId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "success", false,
                    "message", "Authenticator counter regression — possible cloned credential"
            ));
        }
        webAuthnCredentialService.updateSignCount(credential, newSignCount);

        User user = credential.getUser();

        String ip = clientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        UserResponse userResponse = UserResponseMapper.toResponse(user);

        // Bridge the proven passkey (a usernameless Layer-1 factor) INTO the
        // tenant's config-driven APP_LOGIN flow (task #16 B). If the tenant
        // configured Layer-2+ steps we do NOT mint tokens here — we open an
        // MfaSession (currentStep=2, completedMethods=[PASSKEY]) and return
        // MFA_PENDING so the client must complete the remaining steps via
        // /api/v1/auth/mfa/step. Only a 1-step (or no-flow) tenant mints now.
        UsernamelessLoginFlowService.FlowOutcome outcome =
                usernamelessLoginFlowService.continueAfterLayer1(
                        user, AuthMethodType.PASSKEY, "webauthn", ip, userAgent, null);

        if (outcome.mfaPending()) {
            log.info("WebAuthn passkey (usernameless) Layer-1 verified, MFA pending for user: {}, credential: {}",
                    user.getEmail(), credentialId);
            return ResponseEntity.ok(AuthenticationResponse.ofMfaPending(
                    outcome.mfaSessionToken(), outcome.totalSteps(), outcome.currentStep(),
                    null, List.of(), userResponse, List.of(AuthMethodType.PASSKEY.name())));
        }

        log.info("WebAuthn passkey (usernameless) login successful for user: {}, credential: {}",
                user.getEmail(), credentialId);
        return ResponseEntity.ok(AuthenticationResponse.of(
                outcome.accessToken(), outcome.refreshToken(), outcome.expiresIn(), userResponse));
    }

    // --- Phase 2(d): push-token registration for approve-login ---

    /**
     * Stores/refreshes the push-notification token for one of the
     * authenticated user's devices. Backs the approve-login push channel
     * (Phase 3): the approver's device receives the number-matching prompt at
     * this token. The route was previously unmounted even though
     * {@code UserDevice.push_token} + {@code ManageDeviceService.updatePushToken}
     * already existed.
     */
    @PostMapping("/api/v1/devices/push-token")
    @Operation(summary = "Register/refresh a device push-notification token for the current user")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<DeviceResponse> updatePushToken(@RequestBody Map<String, Object> body) {
        Object userIdRaw = body.get("userId");
        String token = (String) body.get("token");
        String platform = (String) body.get("platform");

        if (userIdRaw == null || token == null || token.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        UUID userId;
        try {
            userId = UUID.fromString(userIdRaw.toString());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }

        DeviceResponse updated = manageDeviceUseCase.updatePushToken(userId, token, platform);
        return ResponseEntity.ok(updated);
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
