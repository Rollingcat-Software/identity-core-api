package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;

import java.util.List;
import java.util.UUID;

public interface ManageEnrollmentUseCase {
    List<EnrollmentResponse> getUserEnrollments(UUID userId);
    EnrollmentResponse startEnrollment(UUID userId, UUID tenantId, AuthMethodType methodType);
    EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData);
    void revokeEnrollment(UUID userId, AuthMethodType methodType);
}
