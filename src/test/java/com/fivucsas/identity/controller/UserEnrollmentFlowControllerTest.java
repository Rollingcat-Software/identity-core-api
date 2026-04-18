package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.EnrollmentQueryService;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.BiometricDataRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserEnrollmentFlowController Tests")
class UserEnrollmentFlowControllerTest {

    @Mock private EnrollmentQueryService enrollmentQueryService;
    @Mock private UserEnrollmentRepository enrollmentRepository;
    @Mock private ManageEnrollmentUseCase manageEnrollmentUseCase;
    @Mock private BiometricServicePort biometricService;
    @Mock private BiometricDataRepository biometricDataRepository;
    @Mock private RbacAuthorizationService rbacService;

    @InjectMocks
    private EnrollmentController controller;

    private UUID userId;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        Tenant tenant = Tenant.builder()
                .id(UUID.randomUUID())
                .name("Test Tenant")
                .slug("test-tenant")
                .contactEmail("admin@test.com")
                .status(TenantStatus.ACTIVE)
                .build();
        testUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .tenant(tenant)
                .build();
    }

    @Nested
    @DisplayName("Submit Enrollment")
    class SubmitEnrollment {

        @Test
        @DisplayName("Should submit enrollment successfully")
        void shouldSubmitEnrollment() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            Map<String, Object> enrollResult = new LinkedHashMap<>();
            enrollResult.put("success", true);
            enrollResult.put("quality_score", 92.5);
            enrollResult.put("message", "Face enrolled successfully");
            when(biometricService.enrollFace(eq(userId), any(MultipartFile.class))).thenReturn(enrollResult);

            MultipartFile mockFile = mock(MultipartFile.class);

            ResponseEntity<Map<String, Object>> response = controller.submitEnrollment(
                    "12345678", "1990-01-01", "John Doe", "token-123", "0.95", mockFile);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("status", "COMPLETED");
            assertThat(response.getBody()).containsEntry("qualityScore", 92.5);
            assertThat(response.getBody()).containsEntry("livenessScore", 0.95);
        }

        @Test
        @DisplayName("Should return FAILED status on enrollment failure")
        void shouldReturnFailedOnError() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            Map<String, Object> enrollResult = new LinkedHashMap<>();
            enrollResult.put("success", false);
            enrollResult.put("message", "No face detected");
            when(biometricService.enrollFace(eq(userId), any(MultipartFile.class))).thenReturn(enrollResult);

            MultipartFile mockFile = mock(MultipartFile.class);

            ResponseEntity<Map<String, Object>> response = controller.submitEnrollment(
                    "12345678", "1990-01-01", "John Doe", "token-123", "0.8", mockFile);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("status", "FAILED");
            assertThat(response.getBody()).containsEntry("errorMessage", "No face detected");
        }

        @Test
        @DisplayName("Should handle invalid liveness score")
        void shouldHandleInvalidLivenessScore() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            Map<String, Object> enrollResult = new LinkedHashMap<>();
            enrollResult.put("success", true);
            when(biometricService.enrollFace(eq(userId), any(MultipartFile.class))).thenReturn(enrollResult);

            MultipartFile mockFile = mock(MultipartFile.class);

            ResponseEntity<Map<String, Object>> response = controller.submitEnrollment(
                    "12345678", "1990-01-01", "John Doe", "token-123", "not-a-number", mockFile);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("livenessScore", 0.0);
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());
            MultipartFile mockFile = mock(MultipartFile.class);

            assertThatThrownBy(() -> controller.submitEnrollment(
                    "12345678", "1990-01-01", "John Doe", "token-123", "0.95", mockFile))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }

    @Nested
    @DisplayName("Get Enrollment Status")
    class GetEnrollmentStatus {

        @Test
        @DisplayName("Should return COMPLETED when enrolled")
        void shouldReturnCompletedWhenEnrolled() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            when(biometricDataRepository.findByUserId(userId)).thenReturn(Optional.of(mock()));

            ResponseEntity<Map<String, Object>> response = controller.getEnrollmentStatus();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("status", "COMPLETED");
            assertThat(response.getBody()).containsEntry("qualityScore", 85.0);
        }

        @Test
        @DisplayName("Should return NOT_STARTED when not enrolled")
        void shouldReturnNotStartedWhenNotEnrolled() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            when(biometricDataRepository.findByUserId(userId)).thenReturn(Optional.empty());

            ResponseEntity<Map<String, Object>> response = controller.getEnrollmentStatus();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("status", "NOT_STARTED");
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

            assertThatThrownBy(() -> controller.getEnrollmentStatus())
                    .isInstanceOf(UnauthorizedException.class);
        }
    }

    @Nested
    @DisplayName("Liveness Challenge")
    class LivenessChallenge {

        @Test
        @DisplayName("Should return liveness challenge")
        void shouldReturnLivenessChallenge() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            Map<String, Object> puzzleResult = new LinkedHashMap<>();
            puzzleResult.put("puzzle_id", "puzzle-123");
            puzzleResult.put("steps", List.of("blink", "turn_left"));
            puzzleResult.put("timeout_seconds", 30);
            when(biometricService.generateLivenessPuzzle(userId.toString(), "standard")).thenReturn(puzzleResult);

            ResponseEntity<Map<String, Object>> response = controller.requestLivenessChallenge(null);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("challengeId", "puzzle-123");
            assertThat(response.getBody()).containsEntry("timeoutSeconds", 30);
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

            assertThatThrownBy(() -> controller.requestLivenessChallenge(null))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }

    @Nested
    @DisplayName("Verify Liveness")
    class VerifyLiveness {

        @Test
        @DisplayName("Should verify liveness successfully")
        void shouldVerifyLiveness() {
            // The controller validates liveness locally by counting non-empty frames
            // whose size exceeds 1KB. (Interactive puzzle verification happens
            // client-side via biometric-processor's /liveness/verify endpoint.)
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));

            MultipartFile frame0 = mock(MultipartFile.class);
            when(frame0.isEmpty()).thenReturn(false);
            when(frame0.getSize()).thenReturn(4096L);

            ResponseEntity<Map<String, Object>> response = controller.verifyLiveness("challenge-123", frame0, null, null);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("passed", true);
            assertThat(response.getBody()).containsEntry("token", "challenge-123");
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());
            MultipartFile frame0 = mock(MultipartFile.class);

            assertThatThrownBy(() -> controller.verifyLiveness("challenge-123", frame0, null, null))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }
}
