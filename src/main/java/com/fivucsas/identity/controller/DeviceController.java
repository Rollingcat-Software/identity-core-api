package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.application.service.WebAuthnCredentialService;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.security.TenantScopeResolver;
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

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("sessionId", sessionId.toString());
        options.put("challenge", challenge);
        options.put("rpId", webAuthnService.getRpId());
        options.put("rpName", "Fivucsas Identity");
        options.put("userId", user.getId().toString());
        options.put("userName", user.getEmail());
        options.put("userDisplayName", user.getFirstName() + " " + user.getLastName());
        options.put("excludeCredentials", existingCredentialIds);
        options.put("attestation", "direct");
        options.put("authenticatorSelection", Map.of(
                "requireResidentKey", false,
                "userVerification", "preferred"
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

        WebAuthnCredential credential = WebAuthnCredential.builder()
                .user(user)
                .credentialId(credentialId)
                .publicKey(publicKey)
                .publicKeyAlgorithm(publicKeyAlgorithm)
                .attestationFormat(attestationFormat)
                .transports(transports)
                .deviceName(deviceName)
                .build();

        WebAuthnCredential saved = webAuthnCredentialService.saveCredential(credential);

        log.info("WebAuthn credential registered for user: {}, credentialId: {}", user.getEmail(), credentialId);
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
}
