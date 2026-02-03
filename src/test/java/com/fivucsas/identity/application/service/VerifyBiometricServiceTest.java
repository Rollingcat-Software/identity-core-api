package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricNotEnrolledException;
import com.fivucsas.identity.domain.exception.BiometricVerificationException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.repository.UserRepository;
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

import java.time.LocalDateTime;
import java.util.Map;
import java.time.Instant;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("VerifyBiometricService Tests")
class VerifyBiometricServiceTest {

    // Valid BCrypt hash for testing
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private UserRepository userRepository;

    @Mock
    private BiometricServicePort biometricService;

    @Mock
    private MultipartFile faceImage;

    @InjectMocks
    private VerifyBiometricService verifyBiometricService;

    private User enrolledUser;
    private UUID userId;
    private VerifyBiometricCommand validCommand;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        enrolledUser = User.builder()
            .id(userId)
            .email("test@example.com")
            .passwordHash(VALID_BCRYPT_HASH)
            .firstName("John")
            .lastName("Doe")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(true)
            .verificationCount(0)
            .enrolledAt(Instant.now().minus(Duration.ofDays(10)))
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();

        validCommand = VerifyBiometricCommand.builder()
            .userId(userId.toString())
            .faceImage(faceImage)
            .build();
    }

    @Nested
    @DisplayName("Successful Verification")
    class SuccessfulVerification {

        @Test
        @DisplayName("Should verify biometric successfully")
        void shouldVerifyBiometricSuccessfully() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of(
                    "success", true,
                    "message", "Face verified successfully",
                    "confidence", 0.95
                ));
            when(userRepository.save(any(User.class))).thenReturn(enrolledUser);

            // When
            BiometricResponse response = verifyBiometricService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).isEqualTo("Face verified successfully");
            assertThat(response.getConfidence()).isEqualTo(0.95);
            assertThat(response.getUserId()).isEqualTo(userId.toString());

            verify(userRepository).findById(userId);
            verify(biometricService).verifyFace(userId, faceImage);
            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("Should increment verification count")
        void shouldIncrementVerificationCount() {
            // Given
            int initialCount = enrolledUser.getVerificationCount();
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of("success", true, "confidence", 0.9));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            // When
            verifyBiometricService.execute(validCommand);

            // Then
            assertThat(enrolledUser.getVerificationCount()).isEqualTo(initialCount + 1);
            assertThat(enrolledUser.getLastVerifiedAt()).isNotNull();
            verify(userRepository).save(enrolledUser);
        }

        @Test
        @DisplayName("Should handle integer confidence value")
        void shouldHandleIntegerConfidenceValue() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of(
                    "success", true,
                    "confidence", 1  // Integer instead of Double
                ));
            when(userRepository.save(any(User.class))).thenReturn(enrolledUser);

            // When
            BiometricResponse response = verifyBiometricService.execute(validCommand);

            // Then
            assertThat(response.getConfidence()).isEqualTo(1.0);
        }

        @Test
        @DisplayName("Should return default message when none provided")
        void shouldReturnDefaultMessageWhenNoneProvided() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of("success", true, "confidence", 0.9));
            when(userRepository.save(any(User.class))).thenReturn(enrolledUser);

            // When
            BiometricResponse response = verifyBiometricService.execute(validCommand);

            // Then
            assertThat(response.getMessage()).isEqualTo("Biometric verification successful");
        }
    }

    @Nested
    @DisplayName("Verification Failures")
    class VerificationFailures {

        @Test
        @DisplayName("Should throw UserNotFoundException when user not found")
        void shouldThrowUserNotFoundExceptionWhenUserNotFound() {
            // Given
            UUID nonExistentId = UUID.randomUUID();
            VerifyBiometricCommand command = VerifyBiometricCommand.builder()
                .userId(nonExistentId.toString())
                .faceImage(faceImage)
                .build();

            when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> verifyBiometricService.execute(command))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining(nonExistentId.toString());

            verify(biometricService, never()).verifyFace(any(), any());
        }

        @Test
        @DisplayName("Should throw BiometricNotEnrolledException when user not enrolled")
        void shouldThrowBiometricNotEnrolledExceptionWhenUserNotEnrolled() {
            // Given
            User notEnrolledUser = User.builder()
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

            when(userRepository.findById(userId)).thenReturn(Optional.of(notEnrolledUser));

            // When/Then
            assertThatThrownBy(() -> verifyBiometricService.execute(validCommand))
                .isInstanceOf(BiometricNotEnrolledException.class)
                .hasMessageContaining(userId.toString());

            verify(biometricService, never()).verifyFace(any(), any());
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw BiometricVerificationException when service returns failure")
        void shouldThrowBiometricVerificationExceptionWhenServiceFails() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of(
                    "success", false,
                    "message", "Face does not match"
                ));

            // When/Then
            assertThatThrownBy(() -> verifyBiometricService.execute(validCommand))
                .isInstanceOf(BiometricVerificationException.class)
                .hasMessageContaining("Face does not match");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw exception for invalid UUID format")
        void shouldThrowExceptionForInvalidUuidFormat() {
            // Given
            VerifyBiometricCommand command = VerifyBiometricCommand.builder()
                .userId("invalid-uuid")
                .faceImage(faceImage)
                .build();

            // When/Then
            assertThatThrownBy(() -> verifyBiometricService.execute(command))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle null confidence value")
        void shouldHandleNullConfidenceValue() {
            // Given
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of("success", true, "message", "Verified"));
            when(userRepository.save(any(User.class))).thenReturn(enrolledUser);

            // When
            BiometricResponse response = verifyBiometricService.execute(validCommand);

            // Then
            assertThat(response.getConfidence()).isNull();
        }

        @Test
        @DisplayName("Should handle multiple verifications")
        void shouldHandleMultipleVerifications() {
            // Given
            for (int i = 0; i < 10; i++) {
                enrolledUser.incrementVerificationCount();
            }
            when(userRepository.findById(userId)).thenReturn(Optional.of(enrolledUser));
            when(biometricService.verifyFace(eq(userId), eq(faceImage)))
                .thenReturn(Map.of("success", true, "confidence", 0.98));
            when(userRepository.save(any(User.class))).thenReturn(enrolledUser);

            // When
            verifyBiometricService.execute(validCommand);

            // Then
            assertThat(enrolledUser.getVerificationCount()).isEqualTo(11);
        }
    }
}
