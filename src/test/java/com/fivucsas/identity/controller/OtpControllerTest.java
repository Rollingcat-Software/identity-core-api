package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.sms.VerifiableSmsService;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

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

    /**
     * Regression for USER-BUG-4 (2026-05-01): when production runs with
     * {@code SMS_PROVIDER=twilio-verify}, the SmsService bean is a
     * {@link VerifiableSmsService}. In that mode the provider generates the
     * code itself; the local Redis-backed {@link OtpService} must be bypassed
     * on both send and verify, otherwise the user's correctly-typed Twilio
     * code is compared to an unrelated locally-generated code and rejected.
     */
    @Nested
    @DisplayName("SMS OTP via Twilio Verify (VerifiableSmsService)")
    class SmsOtpViaVerifiableProvider {

        /** Mockito mock that implements both interfaces — mirrors the prod bean. */
        private interface VerifiableSms extends SmsService, VerifiableSmsService {}

        private VerifiableSms verifiableSms;

        @BeforeEach
        void rewireWithVerifiableSms() {
            verifiableSms = mock(VerifiableSms.class);
            ReflectionTestUtils.setField(otpController, "smsService", verifiableSms);
        }

        @Test
        @DisplayName("send: must NOT call OtpService.generate (Twilio mints the code)")
        void sendShouldNotGenerateLocalCode() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));

            ResponseEntity<Map<String, Object>> response = otpController.sendSmsOtp(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            // The bug: pre-fix code called otpService.generate(...) here, putting
            // a code in Redis that verifySmsOtp would later compare against the
            // user-entered Twilio code.
            verify(otpService, never()).generate(any());
            verify(verifiableSms).sendOtp(eq("+905551234567"), any());
        }

        @Test
        @DisplayName("verify: must delegate to VerifiableSmsService.verifyCode, not OtpService.validate")
        void verifyShouldDelegateToProvider() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(verifiableSms.verifyCode("+905551234567", "654321")).thenReturn(true);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "654321"));

            assertThat(response.getBody()).containsEntry("success", true);
            verify(verifiableSms).verifyCode("+905551234567", "654321");
            verify(otpService, never()).validate(any(), any());
        }

        @Test
        @DisplayName("verify: rejects when provider says invalid")
        void verifyRejectsWhenProviderReturnsFalse() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(verifiableSms.verifyCode("+905551234567", "000000")).thenReturn(false);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "000000"));

            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("verify: strips zero-width / bidi marks from carrier-relayed code (NFKC)")
        void verifyNormalizesUnicodeMarks() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            // Provider only ever sees the cleaned digits.
            when(verifiableSms.verifyCode("+905551234567", "654321")).thenReturn(true);

            // U+200E LEFT-TO-RIGHT MARK + U+FEFF ZWNBSP wrapped around digits,
            // plus surrounding whitespace — the kind of payload Turkish carriers
            // sometimes inject before relaying SMS to RCS clients.
            String dirty = " ‎654321﻿ ";
            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", dirty));

            assertThat(response.getBody()).containsEntry("success", true);
            verify(verifiableSms).verifyCode("+905551234567", "654321");
        }
    }

    @Nested
    @DisplayName("Code normalization")
    class CodeNormalization {

        @Test
        @DisplayName("normalizeCode strips whitespace, ZWSP, BOM, LRM/RLM and NFKC-normalizes")
        void normalizesUnicode() {
            assertThat(OtpController.normalizeCode(" 123456 ")).isEqualTo("123456");
            assertThat(OtpController.normalizeCode("​123456‌")).isEqualTo("123456");
            assertThat(OtpController.normalizeCode("‎654321﻿")).isEqualTo("654321");
            // Fullwidth digits → NFKC → ASCII digits
            assertThat(OtpController.normalizeCode("１２３４５６")).isEqualTo("123456");
            assertThat(OtpController.normalizeCode(null)).isNull();
            assertThat(OtpController.normalizeCode("")).isNull();
            assertThat(OtpController.normalizeCode("   ")).isNull();
        }
    }
}
