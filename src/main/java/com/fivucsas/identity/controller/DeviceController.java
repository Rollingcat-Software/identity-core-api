package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

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
@Tag(name = "Devices", description = "Device and WebAuthn/FIDO2 credential management")
public class DeviceController {

    private final ManageDeviceUseCase manageDeviceUseCase;
    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepositoryPort credentialRepository;
    private final UserRepository userRepository;

    // --- /api/v1/devices endpoints ---

    @GetMapping("/api/v1/devices")
    @PreAuthorize("hasPermission(null, 'Device', 'device:read')")
    public ResponseEntity<List<DeviceResponse>> getDevices(
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) UUID tenantId) {
        if (userId != null) {
            return ResponseEntity.ok(manageDeviceUseCase.listUserDevices(userId));
        }
        if (tenantId != null) {
            return ResponseEntity.ok(manageDeviceUseCase.listTenantDevices(tenantId));
        }
        throw new IllegalArgumentException("Either 'userId' or 'tenantId' query parameter is required.");
    }

    @PostMapping("/api/v1/devices")
    @PreAuthorize("hasPermission(null, 'Device', 'device:register')")
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

        credentialRepository.save(credential);

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
                .map(c -> Map.<String, Object>of(
                        "id", c.getId().toString(),
                        "credentialId", c.getCredentialId(),
                        "deviceName", c.getDeviceName() != null ? c.getDeviceName() : "Unknown device",
                        "createdAt", c.getCreatedAt().toString(),
                        "lastUsedAt", c.getLastUsedAt() != null ? c.getLastUsedAt().toString() : "Never"
                ))
                .toList();

        return ResponseEntity.ok(credentials);
    }

    @DeleteMapping("/api/v1/webauthn/credentials/by-id/{id}")
    @Operation(summary = "Delete a WebAuthn credential by database ID")
    @PreAuthorize("isAuthenticated()")
    @Transactional
    public ResponseEntity<Void> deleteCredentialById(@PathVariable UUID id) {
        if (!credentialRepository.existsById(id)) {
            throw new ResourceNotFoundException("Credential", id.toString());
        }
        credentialRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/api/v1/webauthn/credentials/{credentialId}")
    @Operation(summary = "Delete a WebAuthn credential")
    @PreAuthorize("isAuthenticated()")
    @Transactional
    public ResponseEntity<Void> deleteCredential(@PathVariable String credentialId) {
        if (!credentialRepository.existsByCredentialId(credentialId)) {
            throw new ResourceNotFoundException("Credential", credentialId);
        }

        credentialRepository.deleteByCredentialId(credentialId);
        return ResponseEntity.noContent().build();
    }
}
