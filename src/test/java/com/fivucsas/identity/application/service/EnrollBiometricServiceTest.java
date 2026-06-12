package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.EventPublisherPort;
import com.fivucsas.identity.domain.exception.BiometricEnrollmentException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
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
    private UserDomainRepository userDomainRepository;

    @Mock
    private BiometricServicePort biometricService;

    @Mock
    private EventPublisherPort eventPublisher;

    @Mock
    private ManageEnrollmentUseCase manageEnrollmentUseCase;

    @Mock
    private MultipartFile faceImage;

    @Mock
    private ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;

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

    @Nested
    @DisplayName("markBiometricEnrolled (multi-image enroll path)")
    class MarkBiometricEnrolled {

        // Uses the DOMAIN repository + domain User (hexagonal boundary — the service
        // must not touch entity.User here; see UserDomainBoundaryTest).
        private com.fivucsas.identity.domain.model.user.User domainUser(boolean enrolled) {
            return com.fivucsas.identity.domain.model.user.User.builder()
                .id(userId)
                .email("test@example.com")
                .isBiometricEnrolled(enrolled)
                .build();
        }

        @Test
        @DisplayName("Sets enrolled flag + enrolled_at and saves when not yet enrolled")
        void marksEnrolledWhenNotEnrolled() {
            var user = domainUser(false);
            when(userDomainRepository.findById(userId)).thenReturn(Optional.of(user));
            when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            enrollBiometricService.markBiometricEnrolled(userId);

            assertThat(user.hasBiometricEnrolled()).isTrue();
            assertThat(user.getEnrolledAt()).isNotNull();
            verify(userDomainRepository).save(user);
        }

        @Test
        @DisplayName("Is idempotent — no save when already enrolled")
        void noOpWhenAlreadyEnrolled() {
            var user = domainUser(true);
            when(userDomainRepository.findById(userId)).thenReturn(Optional.of(user));

            enrollBiometricService.markBiometricEnrolled(userId);

            verify(userDomainRepository, never()).save(any());
        }

        @Test
        @DisplayName("Throws UserNotFoundException when the user does not exist")
        void throwsWhenUserMissing() {
            UUID missing = UUID.randomUUID();
            when(userDomainRepository.findById(missing)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> enrollBiometricService.markBiometricEnrolled(missing))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining(missing.toString());

            verify(userDomainRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("client-side-embedding routing (Phase 5, sub-project A)")
    class ClientSideEmbeddingRouting {

        private final java.util.List<Double> embedding = java.util.List.of(0.1, 0.2, 0.3);

        @Test
        @DisplayName("policy ON + embedding present → enrollEmbedding, NOT enrollFace (image)")
        void policyOn_embeddingPresent_usesEmbeddingPath() {
            EnrollBiometricCommand command = EnrollBiometricCommand.builder()
                .userId(userId.toString())
                .tenantId("t-marmara")
                .embedding(embedding)
                .build();
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(clientSideEmbeddingPolicy.isEnabledForTenant("t-marmara")).thenReturn(true);
            when(biometricService.enrollEmbedding(eq("t-marmara"), eq(userId), eq(embedding)))
                .thenReturn(Map.of("success", true, "message", "Embedding enrolled"));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            BiometricResponse response = enrollBiometricService.execute(command);

            assertThat(response.isSuccess()).isTrue();
            verify(biometricService).enrollEmbedding("t-marmara", userId, embedding);
            verify(biometricService, never()).enrollFace(any(), any(), any(), any(), any(), anyBoolean());
            // The user enrolled-flag still flips on the embedding path
            assertThat(existingUser.isBiometricEnrolled()).isTrue();
        }

        @Test
        @DisplayName("policy OFF + embedding present → legacy enrollFace (image), embedding ignored")
        void policyOff_embeddingPresent_usesImagePath() {
            EnrollBiometricCommand command = EnrollBiometricCommand.builder()
                .userId(userId.toString())
                .faceImage(faceImage)
                .embedding(embedding)
                .build();
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(clientSideEmbeddingPolicy.isEnabledForTenant((String) null)).thenReturn(false);
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", true));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            BiometricResponse response = enrollBiometricService.execute(command);

            assertThat(response.isSuccess()).isTrue();
            verify(biometricService).enrollFace(userId, faceImage, null, null, null, false);
            verify(biometricService, never()).enrollEmbedding(any(), any(), any());
        }

        @Test
        @DisplayName("policy ON but no embedding (image only) → legacy enrollFace")
        void policyOn_imageOnly_usesImagePath() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            // No embedding in the command, so the routing short-circuits BEFORE
            // consulting the policy — the policy is intentionally NOT stubbed here
            // (a strict-stub error would otherwise flag an unused stub, which is
            // itself the proof that the no-embedding path never touches the gate).
            when(biometricService.enrollFace(eq(userId), eq(faceImage), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", true));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            // validCommand carries faceImage and NO embedding
            BiometricResponse response = enrollBiometricService.execute(validCommand);

            assertThat(response.isSuccess()).isTrue();
            verify(biometricService).enrollFace(userId, faceImage, null, null, null, false);
            verify(biometricService, never()).enrollEmbedding(any(), any(), any());
            verifyNoInteractions(clientSideEmbeddingPolicy);
        }

        @Test
        @DisplayName("embedding path: bio returns success=false → BiometricEnrollmentException, flag not flipped")
        void embeddingPath_bioFailure_throws() {
            EnrollBiometricCommand command = EnrollBiometricCommand.builder()
                .userId(userId.toString())
                .embedding(embedding)
                .build();
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(clientSideEmbeddingPolicy.isEnabledForTenant((String) null)).thenReturn(true);
            when(biometricService.enrollEmbedding(eq(null), eq(userId), eq(embedding)))
                .thenReturn(Map.of("success", false, "message", "Bad embedding"));

            assertThatThrownBy(() -> enrollBiometricService.execute(command))
                .isInstanceOf(BiometricEnrollmentException.class)
                .hasMessageContaining("Bad embedding");
            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("enrollFaceMulti (atomic, transactional flag-flip)")
    class EnrollFaceMulti {

        private com.fivucsas.identity.domain.model.user.User domainUser(boolean enrolled) {
            return com.fivucsas.identity.domain.model.user.User.builder()
                .id(userId)
                .email("test@example.com")
                .isBiometricEnrolled(enrolled)
                .build();
        }

        @Test
        @DisplayName("Success flips is_biometric_enrolled, records scores, and returns the bio response")
        void successFlipsFlagAndRecordsScores() {
            var user = domainUser(false);
            when(biometricService.enrollFaceMulti(eq(userId), any(), eq("t1"), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of(
                    "success", true,
                    "message", "Multi enrolled",
                    "quality_score", 0.9234,
                    "liveness_score", 0.9501));
            when(userDomainRepository.findById(userId)).thenReturn(Optional.of(user));
            when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            Map<String, Object> result = enrollBiometricService.enrollFaceMulti(
                userId, java.util.List.of(faceImage), "t1", null, null, false);

            // Response contract preserved (raw bio map returned unchanged)
            assertThat(result).containsEntry("success", true).containsEntry("message", "Multi enrolled");
            // Flag flipped in the domain user + persisted
            assertThat(user.hasBiometricEnrolled()).isTrue();
            verify(userDomainRepository).save(user);
            // Scores recorded
            verify(manageEnrollmentUseCase).recordBiometricScores(
                eq(userId),
                eq(com.fivucsas.identity.domain.model.auth.AuthMethodType.FACE),
                eq(new java.math.BigDecimal("0.9234")),
                eq(new java.math.BigDecimal("0.9501")));
        }

        @Test
        @DisplayName("Bio failure (success=false) does NOT flip the flag and returns the raw response")
        void bioFailureDoesNotFlipFlag() {
            when(biometricService.enrollFaceMulti(eq(userId), any(), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", false, "message", "Biometric service unavailable"));

            Map<String, Object> result = enrollBiometricService.enrollFaceMulti(
                userId, java.util.List.of(faceImage), null, null, null, false);

            assertThat(result).containsEntry("success", false);
            // No flag flip, no save, no score recording on failure
            verify(userDomainRepository, never()).findById(any());
            verify(userDomainRepository, never()).save(any());
            verify(manageEnrollmentUseCase, never()).recordBiometricScores(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Missing/null 'success' is treated as NOT a success — the flag is never flipped speculatively")
        void missingSuccessKeyDoesNotFlipFlag() {
            // The OLD controller logic used !Boolean.FALSE.equals(success), which
            // flipped the flag when "success" was absent/null. The new robust
            // parsing must NOT flip in that case.
            java.util.Map<String, Object> noSuccessKey = new java.util.HashMap<>();
            noSuccessKey.put("message", "ambiguous");
            when(biometricService.enrollFaceMulti(eq(userId), any(), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(noSuccessKey);

            Map<String, Object> result = enrollBiometricService.enrollFaceMulti(
                userId, java.util.List.of(faceImage), null, null, null, false);

            assertThat(result).containsEntry("message", "ambiguous");
            verify(userDomainRepository, never()).save(any());
            verify(manageEnrollmentUseCase, never()).recordBiometricScores(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Tolerant parsing: string \"true\" success flips the flag (older bio build)")
        void stringTrueSuccessFlipsFlag() {
            var user = domainUser(false);
            java.util.Map<String, Object> stringSuccess = new java.util.HashMap<>();
            stringSuccess.put("success", "true");
            when(biometricService.enrollFaceMulti(eq(userId), any(), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(stringSuccess);
            when(userDomainRepository.findById(userId)).thenReturn(Optional.of(user));
            when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            enrollBiometricService.enrollFaceMulti(
                userId, java.util.List.of(faceImage), null, null, null, false);

            assertThat(user.hasBiometricEnrolled()).isTrue();
            verify(userDomainRepository).save(user);
        }

        @Test
        @DisplayName("Score-writer failure on success must not fail the enrollment, and the flag still flips")
        void scoreWriterFailureStillFlipsFlag() {
            var user = domainUser(false);
            when(biometricService.enrollFaceMulti(eq(userId), any(), eq(null), eq(null), eq(null), eq(false)))
                .thenReturn(Map.of("success", true, "quality_score", 0.9));
            when(userDomainRepository.findById(userId)).thenReturn(Optional.of(user));
            when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            doThrow(new RuntimeException("DB hiccup"))
                .when(manageEnrollmentUseCase)
                .recordBiometricScores(any(), any(), any(), any());

            Map<String, Object> result = enrollBiometricService.enrollFaceMulti(
                userId, java.util.List.of(faceImage), null, null, null, false);

            assertThat(result).containsEntry("success", true);
            assertThat(user.hasBiometricEnrolled()).isTrue();
            verify(userDomainRepository).save(user);
        }

        @Test
        @DisplayName("Idempotent: already-enrolled user is not re-saved on a successful re-enroll")
        void alreadyEnrolledNoResave() {
            var user = domainUser(true);
            when(biometricService.enrollFaceMulti(eq(userId), any(), eq(null), eq(null), eq(null), eq(true)))
                .thenReturn(Map.of("success", true));
            when(userDomainRepository.findById(userId)).thenReturn(Optional.of(user));

            enrollBiometricService.enrollFaceMulti(
                userId, java.util.List.of(faceImage), null, null, null, true);

            verify(userDomainRepository, never()).save(any());
        }
    }
}
