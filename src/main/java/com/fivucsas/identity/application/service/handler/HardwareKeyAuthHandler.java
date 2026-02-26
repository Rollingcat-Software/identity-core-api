package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.repository.WebAuthnCredentialRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class HardwareKeyAuthHandler implements AuthMethodHandler {

    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepository credentialRepository;

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
            // Update sign count to detect cloned authenticators
            long newSignCount = webAuthnService.extractSignCount(authenticatorData);
            if (newSignCount > 0 && newSignCount > credential.getSignCount()) {
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
