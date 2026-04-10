package com.fivucsas.identity.application.service.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Handles fingerprint authentication via WebAuthn platform authenticator.
 * The frontend sends a base64-encoded JSON in the "fingerprintData" field containing:
 * credentialId, authenticatorData, clientDataJSON, signature.
 * This uses the same WebAuthn assertion validation as HardwareKeyAuthHandler,
 * but targets platform authenticators (built-in biometric) rather than cross-platform ones.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class FingerprintAuthHandler implements AuthMethodHandler {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepositoryPort credentialRepository;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.FINGERPRINT;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String action = (String) data.get("action");

        // Phase 1: Generate challenge for the WebAuthn ceremony
        if ("challenge".equals(action)) {
            return generateChallenge(session);
        }

        // Phase 2: Validate the WebAuthn assertion from fingerprintData
        String fingerprintData = (String) data.get("fingerprintData");

        if (fingerprintData == null || fingerprintData.isEmpty()) {
            return StepResult.failure("Fingerprint data is required");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before fingerprint verification");
        }

        // Parse the base64-encoded JSON payload
        String credentialId;
        String authenticatorData;
        String clientDataJson;
        String signature;

        try {
            byte[] decoded = Base64.getDecoder().decode(fingerprintData);
            JsonNode payload = OBJECT_MAPPER.readTree(decoded);

            credentialId = payload.has("credentialId") ? payload.get("credentialId").asText() : null;
            authenticatorData = payload.has("authenticatorData") ? payload.get("authenticatorData").asText() : null;
            clientDataJson = payload.has("clientDataJSON") ? payload.get("clientDataJSON").asText() : null;
            signature = payload.has("signature") ? payload.get("signature").asText() : null;
        } catch (Exception e) {
            log.warn("Failed to parse fingerprintData for session: {}", session.getId(), e);
            return StepResult.failure("Invalid fingerprint data format");
        }

        if (credentialId == null || credentialId.isEmpty()) {
            return StepResult.failure("Credential ID is required");
        }

        // Look up the stored credential to get the public key
        Optional<WebAuthnCredential> credentialOpt = credentialRepository.findByCredentialId(credentialId);
        if (credentialOpt.isEmpty()) {
            log.warn("WebAuthn credential not found: {} for session: {}", credentialId, session.getId());
            return StepResult.failure("Credential not registered");
        }

        WebAuthnCredential credential = credentialOpt.get();

        // Verify the credential belongs to this user
        if (!credential.getUser().getId().equals(session.getUser().getId())) {
            log.warn("WebAuthn credential user mismatch for fingerprint session: {}", session.getId());
            return StepResult.failure("Credential does not belong to this user");
        }

        try {
            boolean valid = webAuthnService.verifyAssertion(
                    session.getId(), credentialId, authenticatorData, clientDataJson,
                    signature, credential.getPublicKey());

            if (valid) {
                // Update sign count to detect cloned authenticators
                long newSignCount = webAuthnService.extractSignCount(authenticatorData);
                if (newSignCount > 0 && newSignCount > credential.getSignCount()) {
                    credential.updateSignCount(newSignCount);
                    credentialRepository.save(credential);
                }

                log.info("Fingerprint (WebAuthn platform) verification successful for user: {}",
                        session.getUser().getEmail());
                return StepResult.success(Map.of("verified", "true"));
            } else {
                log.warn("Fingerprint (WebAuthn platform) verification failed for user: {}",
                        session.getUser().getEmail());
                return StepResult.failure("Fingerprint verification failed");
            }
        } catch (Exception e) {
            log.error("Fingerprint verification error for session: {}", session.getId(), e);
            return StepResult.failure("Fingerprint verification service unavailable");
        }
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("fingerprintData");
    }

    private StepResult generateChallenge(AuthSession session) {
        String challenge = webAuthnService.generateChallenge(session.getId());
        log.info("WebAuthn fingerprint challenge generated for session: {}", session.getId());

        // Include user's stored credential IDs so non-discoverable credentials are found.
        // Without allowCredentials, Android Chrome's passkey picker only shows discoverable
        // credentials — non-resident keys enrolled with requireResidentKey:false won't appear.
        List<String> allowCredentials = session.getUser() != null
                ? credentialRepository.findAllByUserId(session.getUser().getId()).stream()
                    .map(WebAuthnCredential::getCredentialId)
                    .toList()
                : List.of();

        return StepResult.success(Map.of(
                "challenge", challenge,
                "rpId", webAuthnService.getRpId(),
                "authenticatorAttachment", "platform",
                "timeout", "60000",
                "allowCredentials", allowCredentials
        ));
    }
}
