package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("OtpController Tests")
class OtpControllerTest {

    @Mock private OtpService otpService;
    @Mock private EmailService emailService;
    @Mock private SmsService smsService;
    @Mock private UserRepository userRepository;

    @InjectMocks
    private OtpController otpController;

    private UUID userId;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("John")
                .lastName("Doe")
                .phoneNumber("+905551234567")
                .status(UserStatus.ACTIVE)
                .build();
    }

    @Nested
    @DisplayName("Email OTP")
    class EmailOtp {

        @Test
        @DisplayName("Should send email OTP successfully")
        void shouldSendEmailOtp() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(otpService.generate("otp:email:" + userId)).thenReturn("123456");

            ResponseEntity<Map<String, Object>> response = otpController.sendEmailOtp(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("success", true);
            verify(emailService).sendOtp("test@example.com", "123456");
        }

        @Test
        @DisplayName("Should throw when user not found for email OTP")
        void shouldThrowWhenUserNotFound() {
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> otpController.sendEmailOtp(userId))
                    .isInstanceOf(UserNotFoundException.class);
        }

        @Test
        @DisplayName("Should verify email OTP successfully")
        void shouldVerifyEmailOtp() {
            when(otpService.validate("otp:email:" + userId, "123456")).thenReturn(true);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifyEmailOtp(userId, Map.of("code", "123456"));

            assertThat(response.getBody()).containsEntry("success", true);
        }

        @Test
        @DisplayName("Should reject invalid email OTP")
        void shouldRejectInvalidOtp() {
            when(otpService.validate("otp:email:" + userId, "000000")).thenReturn(false);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifyEmailOtp(userId, Map.of("code", "000000"));

            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should reject missing code")
        void shouldRejectMissingCode() {
            ResponseEntity<Map<String, Object>> response =
                    otpController.verifyEmailOtp(userId, Map.of());

            assertThat(response.getStatusCode().value()).isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("SMS OTP")
    class SmsOtp {

        @Test
        @DisplayName("Should send SMS OTP successfully")
        void shouldSendSmsOtp() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(otpService.generate("otp:sms:" + userId)).thenReturn("654321");

            ResponseEntity<Map<String, Object>> response = otpController.sendSmsOtp(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("success", true);
            verify(smsService).sendOtp("+905551234567", "654321");
        }

        @Test
        @DisplayName("Should reject SMS OTP when no phone number")
        void shouldRejectWhenNoPhoneNumber() {
            User userNoPhone = User.builder()
                    .id(userId)
                    .email("test@example.com")
                    .passwordHash("$2a$10$hash")
                    .firstName("John")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .build();

            when(userRepository.findById(userId)).thenReturn(Optional.of(userNoPhone));

            ResponseEntity<Map<String, Object>> response = otpController.sendSmsOtp(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should verify SMS OTP successfully")
        void shouldVerifySmsOtp() {
            when(otpService.validate("otp:sms:" + userId, "654321")).thenReturn(true);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "654321"));

            assertThat(response.getBody()).containsEntry("success", true);
        }
    }
}
