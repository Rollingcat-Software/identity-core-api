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
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class HardwareKeyAuthHandler implements AuthMethodHandler {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepositoryPort credentialRepository;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.HARDWARE_KEY;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String action = (String) data.get("action");

        if ("challenge".equals(action)) {
            return generateChallenge(session);
        }

        String credentialId = (String) data.get("credentialId");
        String authenticatorData = (String) data.get("authenticatorData");
        String clientDataJson = (String) data.get("clientDataJSON");
        String signature = (String) data.get("signature");

        // Frontend may send a base64 JSON blob in "assertion" instead of individual fields
        if (credentialId == null || credentialId.isEmpty()) {
            String assertion = (String) data.get("assertion");
            if (assertion != null && !assertion.isEmpty()) {
                try {
                    byte[] decoded = Base64.getDecoder().decode(assertion);
                    JsonNode payload = OBJECT_MAPPER.readTree(decoded);
                    credentialId = payload.has("credentialId") ? payload.get("credentialId").asText() : null;
                    authenticatorData = payload.has("authenticatorData") ? payload.get("authenticatorData").asText() : authenticatorData;
                    clientDataJson = payload.has("clientDataJSON") ? payload.get("clientDataJSON").asText() : clientDataJson;
                    signature = payload.has("signature") ? payload.get("signature").asText() : signature;
                } catch (Exception e) {
                    log.warn("Failed to parse assertion blob for hardware key session: {}", session.getId(), e);
                    return StepResult.failure("Invalid assertion data format");
                }
            }
        }

        if (credentialId == null || credentialId.isEmpty()) {
            return StepResult.failure("Credential ID is required");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before hardware key verification");
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
            log.warn("WebAuthn credential user mismatch for session: {}", session.getId());
            return StepResult.failure("Credential does not belong to this user");
        }

        boolean valid = webAuthnService.verifyAssertion(
                session.getId(), credentialId, authenticatorData, clientDataJson,
                signature, credential.getPublicKey());

        if (valid) {
            // P1-4: validate the WebAuthn sign-counter per spec §6.1 step 17.
            long newSignCount = webAuthnService.extractSignCount(authenticatorData);
            if (!webAuthnService.validateSignCount(newSignCount, credential.getSignCount())) {
                log.warn("Hardware-key WebAuthn sign-counter regression for session: {} — rejecting (possible cloned credential)",
                        session.getId());
                return StepResult.failure("Authenticator counter regression — possible cloned credential");
            }
            if (newSignCount > credential.getSignCount()) {
                credential.updateSignCount(newSignCount);
                credentialRepository.save(credential);
            }

            log.info("Hardware key verification successful for session: {}", session.getId());
            return StepResult.success(Map.of("verified", "true"));
        } else {
            log.warn("Hardware key verification failed for session: {}", session.getId());
            return StepResult.failure("Hardware key verification failed");
        }
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("credentialId");
    }

    private StepResult generateChallenge(AuthSession session) {
        String challenge = webAuthnService.generateChallenge(session.getId());
        log.info("WebAuthn challenge generated for session: {}", session.getId());
        return StepResult.success(Map.of(
                "challenge", challenge,
                "rpId", webAuthnService.getRpId(),
                "timeout", "60000"
        ));
    }
}
