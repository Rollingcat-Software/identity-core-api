package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.WebAuthnCredentialRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/webauthn")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "WebAuthn/FIDO2", description = "WebAuthn credential registration and management")
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepository credentialRepository;
    private final UserRepository userRepository;

    @PostMapping("/register/options/{userId}")
    @Operation(summary = "Generate WebAuthn registration options (challenge) for credential creation")
    @PreAuthorize("hasAuthority('webauthn:register') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> getRegistrationOptions(@PathVariable UUID userId) {
        log.info("WebAuthn registration options request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));

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

    @PostMapping("/register/verify")
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

        log.info("WebAuthn registration verification for user: {}", userId);

        if (credentialId == null || credentialId.isEmpty() || publicKey == null || publicKey.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "credentialId and publicKey are required"
            ));
        }

        // Validate the challenge was genuine
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
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));

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

        log.info("WebAuthn credential registered for user: {}, credentialId: {}", userId, credentialId);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "success", true,
                "message", "Credential registered successfully",
                "credentialId", credentialId
        ));
    }

    @GetMapping("/credentials/{userId}")
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

    @DeleteMapping("/credentials/{credentialId}")
    @Operation(summary = "Delete a WebAuthn credential")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> deleteCredential(@PathVariable String credentialId) {
        log.info("WebAuthn credential deletion request: {}", credentialId);

        if (!credentialRepository.existsByCredentialId(credentialId)) {
            throw new EntityNotFoundException("Credential not found: " + credentialId);
        }

        credentialRepository.deleteByCredentialId(credentialId);
        return ResponseEntity.noContent().build();
    }
}
