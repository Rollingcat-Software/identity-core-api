package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.entity.WebAuthnCredential;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Service that validates enrollment statuses against actual backing data.
 *
 * The user_enrollments table may report ENROLLED for a method whose real data
 * has been deleted or invalidated. This service cross-checks each enrollment
 * and auto-revokes stale ones so that MFA method selection only shows
 * genuinely usable options.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EnrollmentHealthService {

    private static final String TOTP_SECRET_PREFIX = "totp:secret:";

    /** Methods that are always considered valid when enrolled (no external data to verify). */
    private static final Set<AuthMethodType> ALWAYS_VALID_TYPES = Set.of(
            AuthMethodType.PASSWORD,
            AuthMethodType.QR_CODE
    );

    /** Methods that can be auto-completed on startEnrollment (no async external flow). */
    public static final Set<AuthMethodType> AUTO_COMPLETE_TYPES = Set.of(
            AuthMethodType.PASSWORD,
            AuthMethodType.EMAIL_OTP,
            AuthMethodType.SMS_OTP,
            AuthMethodType.QR_CODE,
            AuthMethodType.NFC_DOCUMENT
    );

    private final UserEnrollmentRepositoryPort userEnrollmentRepository;
    private final UserRepository userRepository;
    private final WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    private final NfcCardRepositoryPort nfcCardRepository;
    private final StringRedisTemplate redisTemplate;
    private final BiometricServicePort biometricServicePort;

    /**
     * Validates all ENROLLED enrollments for a user against actual backing data.
     * Returns a map of method type to whether it is genuinely usable.
     * Stale enrollments (ENROLLED but no backing data) are auto-revoked.
     *
     * @param userId the user whose enrollments to validate
     * @return map of AuthMethodType to validity (true = usable, false = stale/revoked)
     */
    @Transactional
    public Map<AuthMethodType, Boolean> validateEnrollments(UUID userId) {
        List<UserEnrollment> enrollments = userEnrollmentRepository.findAllByUserId(userId);
        Optional<User> userOpt = userRepository.findById(userId);

        if (userOpt.isEmpty()) {
            log.warn("Enrollment health check requested for non-existent user: {}", userId);
            return Collections.emptyMap();
        }

        User user = userOpt.get();
        Map<AuthMethodType, Boolean> healthMap = new EnumMap<>(AuthMethodType.class);

        for (UserEnrollment enrollment : enrollments) {
            if (enrollment.getStatus() != EnrollmentStatus.ENROLLED) {
                healthMap.put(enrollment.getAuthMethodType(), false);
                continue;
            }

            boolean valid = checkBackingData(enrollment.getAuthMethodType(), userId, user);
            healthMap.put(enrollment.getAuthMethodType(), valid);

            if (!valid) {
                log.info("Auto-revoking stale {} enrollment for user {} (backing data missing)",
                        enrollment.getAuthMethodType(), userId);
                enrollment.revoke();
                userEnrollmentRepository.save(enrollment);
            }
        }

        return healthMap;
    }

    /**
     * Checks whether the backing data for a given auth method actually exists.
     */
    private boolean checkBackingData(AuthMethodType methodType, UUID userId, User user) {
        if (ALWAYS_VALID_TYPES.contains(methodType)) {
            return true;
        }

        return switch (methodType) {
            case TOTP -> hasTotpSecret(userId, user);
            case FINGERPRINT -> hasWebAuthnCredential(userId, true);
            case HARDWARE_KEY -> hasWebAuthnCredential(userId, false);
            case FACE -> hasBiometricData(userId, AuthMethodType.FACE);
            case VOICE -> hasBiometricData(userId, AuthMethodType.VOICE);
            case NFC_DOCUMENT -> hasActiveNfcCard(userId);
            case SMS_OTP -> user.getPhoneNumber() != null && !user.getPhoneNumber().isBlank();
            case EMAIL_OTP -> user.getEmail() != null && !user.getEmail().isBlank();
            default -> true; // Unknown future types default to valid
        };
    }

    /**
     * TOTP is valid if the user has a two_factor_secret in the DB or a secret in Redis.
     */
    private boolean hasTotpSecret(UUID userId, User user) {
        if (user.getTwoFactorSecret() != null && !user.getTwoFactorSecret().isBlank()) {
            return true;
        }
        try {
            String redisKey = TOTP_SECRET_PREFIX + userId;
            return Boolean.TRUE.equals(redisTemplate.hasKey(redisKey));
        } catch (Exception e) {
            log.warn("Redis unavailable during TOTP health check for user {}: {}", userId, e.getMessage());
            // Fail open: if Redis is down but DB has no secret, consider it invalid
            return false;
        }
    }

    /**
     * Checks for WebAuthn credentials, distinguishing platform (fingerprint) from
     * cross-platform (hardware key) authenticators based on the transports field.
     *
     * @param platformAuthenticator true for FINGERPRINT (internal transport),
     *                              false for HARDWARE_KEY (usb, ble, nfc)
     */
    private boolean hasWebAuthnCredential(UUID userId, boolean platformAuthenticator) {
        List<WebAuthnCredential> credentials = webAuthnCredentialRepository.findAllByUserId(userId);
        if (credentials.isEmpty()) {
            return false;
        }

        for (WebAuthnCredential credential : credentials) {
            String transports = credential.getTransports();
            boolean isInternal = transports != null && transports.toLowerCase().contains("internal");

            if (platformAuthenticator && isInternal) {
                return true;
            }
            if (!platformAuthenticator && !isInternal) {
                return true;
            }
        }

        // Has credentials but none match the expected transport type.
        // Only consider it valid if some credentials have NO transport metadata (null/blank),
        // since we can't distinguish platform vs cross-platform in that case.
        // If all credentials have explicit transport types that don't match, it's invalid.
        return credentials.stream().anyMatch(c ->
                c.getTransports() == null || c.getTransports().isBlank());
    }

    /**
     * Checks whether biometric data (face/voice) exists for the user.
     * Biometric embeddings live in biometric_db (separate database managed by biometric-processor),
     * NOT in the enrollment_data field of user_enrollments (which is always "{}").
     * We trust the enrollment status if the biometric service is healthy.
     * If the service is down, fail open (don't revoke).
     */
    private boolean hasBiometricData(UUID userId, AuthMethodType biometricType) {
        try {
            Map<String, Object> health = biometricServicePort.checkHealth();
            String status = health != null ? String.valueOf(health.getOrDefault("status", "")) : "";
            if (!"ok".equalsIgnoreCase(status) && !"healthy".equalsIgnoreCase(status)) {
                log.warn("Biometric service unhealthy during {} health check for user {}", biometricType, userId);
            }
            // Biometric data is in biometric_db (face_embeddings/voice_enrollments tables).
            // We cannot query it from identity-core-api. Trust the enrollment if service is reachable.
            return true;
        } catch (Exception e) {
            log.warn("Biometric service unreachable during {} health check for user {}: {}",
                    biometricType, userId, e.getMessage());
            // Fail open: don't revoke when service is unreachable
            return true;
        }
    }

    /**
     * Checks whether the user has at least one active NFC card.
     */
    private boolean hasActiveNfcCard(UUID userId) {
        List<NfcCard> activeCards = nfcCardRepository.findByUserIdAndIsActiveTrue(userId);
        return !activeCards.isEmpty();
    }
}
