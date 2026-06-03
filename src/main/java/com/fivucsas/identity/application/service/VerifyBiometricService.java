package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricNotEnrolledException;
import com.fivucsas.identity.domain.exception.BiometricVerificationException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

/**
 * Use case service for biometric verification.
 *
 * Implements the VerifyBiometricUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyBiometricService implements VerifyBiometricUseCase {

    private final UserRepository userRepository;
    private final BiometricServicePort biometricService;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;
    private final com.fivucsas.identity.application.port.output.BiometricConsentResolver consentResolver;

    @Override
    @Transactional
    public BiometricResponse execute(VerifyBiometricCommand command) {
        log.info("Verifying biometric for user: {}", command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // The bio face store is keyed by user_id. By default we verify against the
        // requesting user's own embedding under their own tenant.
        UUID targetUserId = userId;
        String targetTenantId = command.getTenantId();

        // TODO(flag-consistency): the verify gate keys off the denormalized
        // users.is_biometric_enrolled boolean, which can drift out of sync with
        // the bio embedding store (the "enrolled-but-412" class this PR addresses
        // on the WRITE side + via the admin reconciler). The more robust long-term
        // fix is to gate on actual embedding presence — e.g. consult
        // BiometricServicePort.hasEnrollment(userId, tenant) when the flag is false
        // before throwing BiometricNotEnrolledException. NOT changed here: this is
        // a security-sensitive, hot verify path and warrants its own well-tested PR
        // (adds a bio round-trip + must stay fail-closed on bio errors).
        if (!user.isBiometricEnrolled()) {
            // Model A, Phase 3 — consent-gated cross-tenant verify. The requesting
            // user has NO local FACE enrollment. If the SAME PERSON (identity) has
            // a canonical FACE enrollment under another membership AND has granted
            // this requesting tenant consent, route the verify to that canonical
            // embedding. Otherwise behave EXACTLY as "not enrolled" — leaking no
            // signal that a template exists elsewhere (default-DENY).
            var canonical = consentResolver.resolveConsentedCanonicalTarget(
                    userId, AuthMethodType.FACE.name());
            if (canonical.isEmpty()) {
                throw new BiometricNotEnrolledException(command.getUserId());
            }
            targetUserId = canonical.get().canonicalUserId();
            // Forward the CANONICAL tenant so tenant-scoped bio predicates keep
            // matching the embedding that actually lives there.
            targetTenantId = canonical.get().canonicalTenantId().toString();
        }

        // Call external biometric service. Forward tenant_id +
        // client_embedding(s) for tenant-scoped pgvector matching and
        // D2 log-only client telemetry.
        Map<String, Object> response = biometricService.verifyFace(
                targetUserId,
                command.getFaceImage(),
                targetTenantId,
                command.getClientEmbedding(),
                command.getClientEmbeddings());

        // biometric-processor returns "verified" (boolean), "confidence" (double),
        // "distance" (cosine distance, lower is better) and "threshold"
        // (the value distance was compared against). The latter two are
        // surfaced to the SPA via BiometricVerificationResponse so the UI can
        // stop synthesising fake sentinels (INVESTIGATION_MASTER_2026-05-07
        // §wires).
        Boolean verified = response.get("verified") != null
            ? (Boolean) response.get("verified")
            : (Boolean) response.get("success");
        String message = (String) response.get("message");
        Double confidence = numericOrNull(response.get("confidence"));
        Double distance = numericOrNull(response.get("distance"));
        Double threshold = numericOrNull(response.get("threshold"));

        if (!Boolean.TRUE.equals(verified)) {
            throw new BiometricVerificationException("Face verification failed: " + message);
        }

        // Update verification count
        user.incrementVerificationCount();
        userRepository.save(user);

        log.info("Biometric verified successfully for user: {}", user.getId());
        eventPublisher.publishBiometricVerified(command.getUserId(), true);

        return BiometricResponse.builder()
            .success(true)
            .message(message != null ? message : "Biometric verification successful")
            .confidence(confidence)
            .distance(distance)
            .threshold(threshold)
            .userId(command.getUserId())
            .build();
    }

    /**
     * Defensive numeric coercion — bio processor responses are loose maps,
     * so a value can land as {@link Number}, missing, or unexpectedly typed.
     * Returns {@code null} on any non-Number / null input rather than blowing
     * the verify response up over a telemetry field.
     */
    private static Double numericOrNull(Object value) {
        return value instanceof Number n ? n.doubleValue() : null;
    }
}
