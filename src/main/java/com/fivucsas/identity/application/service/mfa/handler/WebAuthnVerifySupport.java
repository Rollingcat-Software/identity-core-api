package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.application.service.WebAuthnCredentialService;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared WebAuthn helper used by both
 * {@link FingerprintVerifyMfaStepHandler} (platform authenticators) and
 * {@link HardwareKeyVerifyMfaStepHandler} (cross-platform / roaming
 * authenticators).
 *
 * <p>The two methods differ ONLY in the transport filter applied when
 * generating the {@code allowCredentials} list during the challenge phase
 * — platform authenticators carry the {@code internal} transport, hardware
 * keys do not. The verification path is identical.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class WebAuthnVerifySupport {

    private final WebAuthnService webAuthnService;
    private final WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    private final WebAuthnCredentialService webAuthnCredentialService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Build a WebAuthn challenge response for the supplied transport class.
     *
     * @param wantPlatform {@code true} for FINGERPRINT (platform authenticator),
     *                     {@code false} for HARDWARE_KEY (roaming authenticator).
     */
    Map<String, Object> buildChallengeResponse(MfaSession session, User user, boolean wantPlatform) {
        String challenge = webAuthnService.generateChallenge(session.getId());
        List<String> allowCredentials = webAuthnCredentialRepository
                .findAllByUserId(user.getId()).stream()
                .filter(c -> {
                    String t = c.getTransports();
                    if (t == null || t.isBlank()) return true;
                    boolean isInternal = t.toLowerCase().contains("internal");
                    return wantPlatform == isInternal;
                })
                .map(WebAuthnCredential::getCredentialId)
                .toList();

        Map<String, Object> body = new HashMap<>();
        body.put("status", "CHALLENGE");
        body.put("data", Map.of(
                "challenge", challenge,
                "rpId", webAuthnService.getRpId(),
                "timeout", "60000",
                "allowCredentials", allowCredentials
        ));
        return body;
    }

    /** Verify a base64-encoded WebAuthn assertion JSON against the user's stored credential. */
    MfaStepResult verifyAssertion(MfaSession session, User user, String assertionRaw) {
        if (assertionRaw == null || assertionRaw.isBlank()) {
            log.warn("MFA WebAuthn: assertion field is null/blank");
            return MfaStepResult.fail();
        }
        try {
            String assertionJson = new String(Base64.getDecoder().decode(assertionRaw));
            var node = objectMapper.readTree(assertionJson);

            String credentialId = node.get("credentialId").asText();
            String authenticatorData = node.get("authenticatorData").asText();
            String clientDataJSON = node.get("clientDataJSON").asText();
            String signature = node.get("signature").asText();

            var credentialOpt = webAuthnCredentialRepository.findByCredentialId(credentialId);
            if (credentialOpt.isEmpty()) {
                log.warn("WebAuthn credential not found: {}", credentialId);
                return MfaStepResult.fail();
            }
            var credential = credentialOpt.get();

            if (!credential.getUser().getId().equals(user.getId())) {
                log.warn("WebAuthn credential {} does not belong to user {}", credentialId, user.getId());
                return MfaStepResult.fail();
            }

            boolean verified = webAuthnService.verifyAssertion(
                    session.getId(), credentialId, authenticatorData,
                    clientDataJSON, signature, credential.getPublicKey());

            if (verified) {
                // P1-4: validate the WebAuthn sign-counter per spec §6.1 step 17.
                long newSignCount = webAuthnService.extractSignCount(authenticatorData);
                if (!webAuthnService.validateSignCount(newSignCount, credential.getSignCount())) {
                    log.warn("MFA WebAuthn sign-counter regression for user: {} cred: {} — rejecting (possible cloned credential)",
                            user.getEmail(), credentialId);
                    return MfaStepResult.fail();
                }
                webAuthnCredentialService.updateSignCount(credential, newSignCount);
            }
            return verified ? MfaStepResult.ok() : MfaStepResult.fail();
        } catch (Exception e) {
            log.error("WebAuthn assertion verification failed", e);
            return MfaStepResult.fail();
        }
    }
}
