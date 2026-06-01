package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.EventPublisherPort;
import com.fivucsas.identity.domain.exception.BiometricEnrollmentException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("EnrollBiometricService Tests")
class EnrollBiometricServiceTest {

    @Test
    @DisplayName("extractScore parses and clamps numeric scores to [0, 1]")
    void extractScoreParsesAndClamps() {
        java.util.Map<String, Object> raw = java.util.Map.of(
                "quality_score", 0.9234,
                "liveness_score", "0.95",
                "ratio_score", 87.5,           // 0..100 percent style → rescaled
                "negative_score", -0.5,        // clamped to 0
                "huge_score", 5_000_000.0      // out of range → clamped to 1
        );
        assertThat(EnrollBiometricService.extractScore(raw, "quality_score"))
                .isEqualByComparingTo(new java.math.BigDecimal("0.9234"));
        assertThat(EnrollBiometricService.extractScore(raw, "liveness_score"))
                .isEqualByComparingTo(new java.math.BigDecimal("0.9500"));
        assertThat(EnrollBiometricService.extractScore(raw, "ratio_score"))
                .isEqualByComparingTo(new java.math.BigDecimal("0.8750"));
        assertThat(EnrollBiometricService.extractScore(raw, "negative_score"))
                .isEqualByComparingTo(java.math.BigDecimal.ZERO);
        assertThat(EnrollBiometricService.extractScore(raw, "huge_score"))
                .isEqualByComparingTo(java.math.BigDecimal.ONE);
        assertThat(EnrollBiometricService.extractScore(raw, "missing_score")).isNull();
        assertThat(EnrollBiometricService.extractScore(null, "quality_score")).isNull();
    }


    // Valid BCrypt hash for testing
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private UserRepository userRepository;

    @Mock
    private BiometricServicePort biometricService;

    @Mock
    private EventPublisherPort eventPublisher;

    @Mock
    private ManageEnrollmentUseCase manageEnrollmentUseCase;

    @Mock
    private MultipartFile faceImage;

    @InjectMocks
    private EnrollBiometricService enrollBiometricService;

    private User existingUser;
    private UUID userId;
    private EnrollBiometricCommand validCommand;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        existingUser = User.builder()
            .id(userId)
            .email("test@example.com")
            .passwordHash(VALID_BCRYPT_HASH)
            .firstName("John")
            .lastName("Doe")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();

        validCommand = EnrollBiometricCommand.builder()
            .userId(userId.toString())
            .faceImage(faceImage)
            .build();
    }

    @Nested
    @DisplayName("Successful Enrollment")
    class SuccessfulEnrollment {

        @Test
        @DisplayName("Should enroll biometric successfully")
        void shouldEnrollBiometricSuccessfully() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of(
                    "success", true,
                    "message", "Face enrolled successfully"
                ));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            // When
            BiometricResponse response = enrollBiometricService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).isEqualTo("Face enrolled successfully");
            assertThat(response.getUserId()).isEqualTo(userId.toString());

            verify(userRepository).findById(userId);
            verify(biometricService).enrollFace(userId, faceImage, null, null, null, false);
            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("Should forward optimize=true to the biometric service on re-enroll & optimize")
        void shouldForwardOptimizeFlag() {
            // Given a re-enroll & optimize command
            EnrollBiometricCommand optimizeCommand = EnrollBiometricCommand.builder()
                .userId(userId.toString())
                .faceImage(faceImage)
                .optimize(true)
                .build();
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(true)))
                .thenReturn(Map.of("success", true, "message", "Face enrolled successfully"));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            // When
            BiometricResponse response = enrollBiometricService.execute(optimizeCommand);

            // Then the optimize flag reaches the biometric service unchanged
            assertThat(response.isSuccess()).isTrue();
            verify(biometricService).enrollFace(userId, faceImage, null, null, null, true);
        }

        @Test
        @DisplayName("Should persist quality + liveness scores from biometric-processor response")
        void shouldPersistScoresFromBiometricProcessorResponse() {
            // Given — biometric-processor returns quality_score + liveness_score
            // alongside success. The writer must surface them onto the
            // user_enrollments row so the admin Enrollments table renders
            // real numbers instead of "-".
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of(
                    "success", true,
                    "message", "Face enrolled",
                    "quality_score", 0.9234,
                    "liveness_score", 0.9501
                ));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            // When
            enrollBiometricService.execute(validCommand);

            // Then — scores parsed from raw response and forwarded to writer
            verify(manageEnrollmentUseCase).recordBiometricScores(
                eq(userId),
                eq(com.fivucsas.identity.domain.model.auth.AuthMethodType.FACE),
                eq(new java.math.BigDecimal("0.9234")),
                eq(new java.math.BigDecimal("0.9501"))
            );
        }

        @Test
        @DisplayName("Score-writer failure must not fail the enrollment itself")
        void scoreWriterFailureShouldNotFailEnrollment() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of(
                    "success", true,
                    "quality_score", 0.91
                ));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);
            doThrow(new RuntimeException("DB hiccup"))
                .when(manageEnrollmentUseCase)
                .recordBiometricScores(any(), any(), any(), any());

            // When — must not throw
            BiometricResponse response = enrollBiometricService.execute(validCommand);

            // Then
            assertThat(response.isSuccess()).isTrue();
            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("Should update user enrollment status")
        void shouldUpdateUserEnrollmentStatus() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", true));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            // When
            enrollBiometricService.execute(validCommand);

            // Then
            assertThat(existingUser.isBiometricEnrolled()).isTrue();
            assertThat(existingUser.getEnrolledAt()).isNotNull();
            verify(userRepository).save(existingUser);
        }

        @Test
        @DisplayName("Should return default message when none provided")
        void shouldReturnDefaultMessageWhenNoneProvided() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", true));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            // When
            BiometricResponse response = enrollBiometricService.execute(validCommand);

            // Then
            assertThat(response.getMessage()).isEqualTo("Biometric enrollment successful");
        }
    }

    @Nested
    @DisplayName("Enrollment Failures")
    class EnrollmentFailures {

        @Test
        @DisplayName("Should throw UserNotFoundException when user not found")
        void shouldThrowUserNotFoundExceptionWhenUserNotFound() {
            // Given
            UUID nonExistentId = UUID.randomUUID();
            EnrollBiometricCommand command = EnrollBiometricCommand.builder()
                .userId(nonExistentId.toString())
                .faceImage(faceImage)
                .build();

            when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> enrollBiometricService.execute(command))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining(nonExistentId.toString());

            verify(biometricService, never()).enrollFace(any(), any(), any(), any(), any(), anyBoolean());
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw BiometricEnrollmentException when service returns failure")
        void shouldThrowBiometricEnrollmentExceptionWhenServiceFails() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of(
                    "success", false,
                    "message", "Poor image quality"
                ));

            // When/Then
            assertThatThrownBy(() -> enrollBiometricService.execute(validCommand))
                .isInstanceOf(BiometricEnrollmentException.class)
                .hasMessageContaining("Poor image quality");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw BiometricEnrollmentException when success is null")
        void shouldThrowBiometricEnrollmentExceptionWhenSuccessIsNull() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("message", "Unknown error"));

            // When/Then
            assertThatThrownBy(() -> enrollBiometricService.execute(validCommand))
                .isInstanceOf(BiometricEnrollmentException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw exception for invalid UUID format")
        void shouldThrowExceptionForInvalidUuidFormat() {
            // Given
            EnrollBiometricCommand command = EnrollBiometricCommand.builder()
                .userId("invalid-uuid")
                .faceImage(faceImage)
                .build();

            // When/Then
            assertThatThrownBy(() -> enrollBiometricService.execute(command))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle re-enrollment of already enrolled user")
        void shouldHandleReEnrollment() {
            // Given
            User enrolledUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(true)
                .verificationCount(5)
                .enrolledAt(Instant.now().minus(Duration.ofDays(10)))
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", true, "message", "Re-enrollment successful"));
            when(userRepository.save(any(User.class))).thenReturn(enrolledUser);

            // When
            BiometricResponse response = enrollBiometricService.execute(validCommand);

            // Then
            assertThat(response.isSuccess()).isTrue();
            verify(userRepository).save(any(User.class));
        }
    }
}
