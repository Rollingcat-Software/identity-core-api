package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class HardwareKeyAuthHandler implements AuthMethodHandler {

    private final WebAuthnService webAuthnService;

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

        boolean valid = webAuthnService.verifyAssertion(
                session.getId(), credentialId, authenticatorData, clientDataJson, signature);

        if (valid) {
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
                "rpId", "fivucsas.rollingcatsoftware.com",
                "timeout", "60000"
        ));
    }
}
