package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class ManageEnrollmentService implements ManageEnrollmentUseCase {

    private static final Set<AuthMethodType> BIOMETRIC_TYPES = Set.of(
            AuthMethodType.FACE, AuthMethodType.FINGERPRINT, AuthMethodType.VOICE);

    private final UserEnrollmentRepositoryPort userEnrollmentRepository;
    private final UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;
    private final BiometricServicePort biometricServicePort;
    private final NfcCardRepositoryPort nfcCardRepository;
    private final WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;

    @Override
    @Transactional
    public List<EnrollmentResponse> getUserEnrollments(UUID userId) {
        ensureEmailOtpEnrollment(userId);
        return userEnrollmentRepository.findAllByUserId(userId).stream()
                .map(EnrollmentResponse::from)
                .toList();
    }

    /**
     * EMAIL_OTP is not really an "enrollable" method — every user has an
     * email bound at registration, so the auth-methods UI should always show
     * EMAIL_OTP as enrolled. Lazily upsert a status=ENROLLED row the first
     * time a user's enrollments are listed so the UI doesn't have to special-
     * case it. Idempotent: existing rows (including REVOKED) are left alone.
     */
    private void ensureEmailOtpEnrollment(UUID userId) {
        if (userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, AuthMethodType.EMAIL_OTP)
                .isPresent()) {
            return;
        }
        userRepository.findById(userId).ifPresent(user -> {
            if (user.getEmail() == null || user.getEmail().isBlank()) {
                return;
            }
            if (user.getTenant() == null) {
                return;
            }
            UserEnrollment enrollment = UserEnrollment.builder()
                    .user(user)
                    .tenant(user.getTenant())
                    .authMethodType(AuthMethodType.EMAIL_OTP)
                    .build();
            enrollment.completeEnrollment("{}");
            try {
                userEnrollmentRepository.save(enrollment);
            } catch (Exception e) {
                // Race: another concurrent request already inserted the row.
                // Safe to swallow — next read will see it.
                log.debug("EMAIL_OTP auto-enrollment skipped for user {}: {}",
                        userId, e.getMessage());
            }
        });
    }

    @Override
    @Transactional
    public EnrollmentResponse startEnrollment(UUID userId, UUID tenantId, AuthMethodType methodType) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseGet(() -> {
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
                    Tenant tenant = tenantRepository.findById(tenantId)
                            .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));
                    return UserEnrollment.builder()
                            .user(user)
                            .tenant(tenant)
                            .authMethodType(methodType)
                            .build();
                });

        // Only auto-complete for methods that don't require external async data
        // (PASSWORD, EMAIL_OTP, SMS_OTP, QR_CODE, NFC_DOCUMENT). All others stay
        // PENDING until the actual enrollment flow completes via completeEnrollment().
        if (EnrollmentHealthService.AUTO_COMPLETE_TYPES.contains(methodType)) {
            enrollment.completeEnrollment("{}");
        } else {
            enrollment.startEnrollment();
        }
        return EnrollmentResponse.from(userEnrollmentRepository.save(enrollment));
    }

    @Override
    @Transactional
    public EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData) {
        return completeEnrollment(userId, methodType, enrollmentData, null, null);
    }

    @Override
    @Transactional
    public EnrollmentResponse completeEnrollment(UUID userId,
                                                 AuthMethodType methodType,
                                                 String enrollmentData,
                                                 BigDecimal qualityScore,
                                                 BigDecimal livenessScore) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseThrow(() -> new EntityNotFoundException("Enrollment not found for user: " + userId + " method: " + methodType));

        enrollment.completeEnrollment(enrollmentData, qualityScore, livenessScore);
        return EnrollmentResponse.from(userEnrollmentRepository.save(enrollment));
    }

    /**
     * Best-effort score update: persists biometric quality + liveness scores on
     * an existing enrollment row when one exists. Used by biometric enrollment
     * endpoints (face/voice) to record scores even when the row was already
     * marked ENROLLED via a separate /complete call. Silently no-ops when no
     * enrollment exists yet, so the biometric upload itself never fails because
     * of bookkeeping.
     */
    @Override
    @Transactional
    public void recordBiometricScores(UUID userId,
                                       AuthMethodType methodType,
                                       BigDecimal qualityScore,
                                       BigDecimal livenessScore) {
        if (qualityScore == null && livenessScore == null) {
            return;
        }
        userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, methodType)
                .ifPresent(enrollment -> {
                    enrollment.recordScores(qualityScore, livenessScore);
                    userEnrollmentRepository.save(enrollment);
                });
    }

    @Override
    @Transactional
    public void revokeEnrollment(UUID userId, AuthMethodType methodType) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseThrow(() -> new EntityNotFoundException("Enrollment not found for user: " + userId + " method: " + methodType));

        // Clean up backing data for methods that have external storage
        if (BIOMETRIC_TYPES.contains(methodType)) {
            deleteBiometricData(userId, methodType);
        }
        cleanupMethodData(userId, methodType);

        enrollment.revoke();
        userEnrollmentRepository.save(enrollment);
    }

    private void cleanupMethodData(UUID userId, AuthMethodType methodType) {
        try {
            switch (methodType) {
                case NFC_DOCUMENT -> {
                    List<NfcCard> cards = nfcCardRepository.findByUserIdAndIsActiveTrue(userId);
                    for (NfcCard card : cards) {
                        card.deactivate();
                        nfcCardRepository.save(card);
                    }
                    if (!cards.isEmpty()) {
                        log.info("Deactivated {} NFC cards for user: {}", cards.size(), userId);
                    }
                }
                case HARDWARE_KEY -> {
                    // Hardware keys have transports like "usb", "nfc", "ble" (not "internal")
                    var credentials = webAuthnCredentialRepository.findAllByUserId(userId).stream()
                            .filter(c -> c.getTransports() == null || !c.getTransports().contains("internal"))
                            .toList();
                    for (var cred : credentials) {
                        webAuthnCredentialRepository.deleteById(cred.getId());
                    }
                    if (!credentials.isEmpty()) {
                        log.info("Deleted {} hardware key credentials for user: {}", credentials.size(), userId);
                    }
                }
                case FINGERPRINT -> {
                    // Platform authenticators have "internal" transport
                    var credentials = webAuthnCredentialRepository.findAllByUserId(userId).stream()
                            .filter(c -> c.getTransports() != null && c.getTransports().contains("internal"))
                            .toList();
                    for (var cred : credentials) {
                        webAuthnCredentialRepository.deleteById(cred.getId());
                    }
                    if (!credentials.isEmpty()) {
                        log.info("Deleted {} fingerprint credentials for user: {}", credentials.size(), userId);
                    }
                }
                default -> { /* no additional cleanup needed */ }
            }
        } catch (Exception e) {
            log.warn("Failed to clean up {} data for user: {}. Revocation will proceed. Error: {}",
                    methodType, userId, e.getMessage());
        }
    }

    private void deleteBiometricData(UUID userId, AuthMethodType methodType) {
        try {
            switch (methodType) {
                case FACE -> biometricServicePort.deleteFace(userId);
                case FINGERPRINT -> biometricServicePort.deleteFingerprint(userId);
                case VOICE -> biometricServicePort.deleteVoice(userId);
                default -> { /* no-op for non-biometric types */ }
            }
            log.info("Biometric data deleted from external service for user: {} method: {}", userId, methodType);
        } catch (Exception e) {
            log.warn("Failed to delete biometric data from external service for user: {} method: {}. " +
                     "Enrollment revocation will proceed. Error: {}", userId, methodType, e.getMessage());
        }
    }
}
