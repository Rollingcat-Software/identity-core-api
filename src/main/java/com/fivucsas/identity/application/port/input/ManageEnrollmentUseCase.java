package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

public interface ManageEnrollmentUseCase {
    List<EnrollmentResponse> getUserEnrollments(UUID userId);
    EnrollmentResponse startEnrollment(UUID userId, UUID tenantId, AuthMethodType methodType);
    EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData);

    /**
     * Complete an enrollment and persist biometric quality + liveness scores
     * captured from the biometric-processor response. Either score may be
     * {@code null} (e.g. for non-biometric methods).
     */
    EnrollmentResponse completeEnrollment(UUID userId,
                                          AuthMethodType methodType,
                                          String enrollmentData,
                                          BigDecimal qualityScore,
                                          BigDecimal livenessScore);

    /**
     * Best-effort score recording: persists biometric quality and/or liveness
     * scores on an existing enrollment row without changing its status or
     * {@code enrolledAt} timestamp. Silently no-ops when no enrollment row
     * exists yet, so the biometric upload itself must not fail because of
     * admin bookkeeping.
     */
    void recordBiometricScores(UUID userId,
                               AuthMethodType methodType,
                               BigDecimal qualityScore,
                               BigDecimal livenessScore);

    void revokeEnrollment(UUID userId, AuthMethodType methodType);
}
