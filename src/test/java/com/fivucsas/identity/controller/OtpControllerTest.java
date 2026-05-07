package com.fivucsas.identity.controller;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.sms.VerifiableSmsService;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
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
            when(otpService.validateWithResult("otp:email:" + userId, "123456"))
                    .thenReturn(OtpService.ValidationResult.valid());

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifyEmailOtp(userId, Map.of("code", "123456"));

            assertThat(response.getBody()).containsEntry("success", true);
        }

        @Test
        @DisplayName("Should reject invalid email OTP")
        void shouldRejectInvalidOtp() {
            when(otpService.validateWithResult("otp:email:" + userId, "000000"))
                    .thenReturn(OtpService.ValidationResult.invalid(4));

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifyEmailOtp(userId, Map.of("code", "000000"));

            assertThat(response.getBody())
                    .containsEntry("success", false)
                    .containsEntry("errorCode", "OTP_INVALID")
                    .containsEntry("remainingAttempts", 4L);
        }

        @Test
        @DisplayName("Should report OTP_ATTEMPTS_EXHAUSTED on the 5th wrong guess")
        void shouldReportExhaustedOnFifthWrongGuess() {
            when(otpService.validateWithResult("otp:email:" + userId, "000000"))
                    .thenReturn(OtpService.ValidationResult.exhausted());

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifyEmailOtp(userId, Map.of("code", "000000"));

            assertThat(response.getBody())
                    .containsEntry("success", false)
                    .containsEntry("errorCode", "OTP_ATTEMPTS_EXHAUSTED")
                    .containsEntry("remainingAttempts", 0);
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
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(otpService.validateWithResult("otp:sms:" + userId, "654321"))
                    .thenReturn(OtpService.ValidationResult.valid());

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "654321"));

            assertThat(response.getBody()).containsEntry("success", true);
        }

        @Test
        @DisplayName("verify: rejects unknown userId even in local-OTP mode (consistent with Verifiable mode)")
        void verifyRejectsUnknownUserInLocalMode() {
            // Pre-fix: local-OTP path skipped the User lookup and returned
            // 200 `{success:false}` for a nonexistent userId, while the
            // Verifiable path threw 404. Now both paths consistently 404.
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() ->
                    otpController.verifySmsOtp(userId, Map.of("code", "654321")))
                    .isInstanceOf(UserNotFoundException.class);
            verify(otpService, never()).validate(any(), any());
            verify(otpService, never()).validateWithResult(any(), any());
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
        private Logger otpControllerLogger;
        private ListAppender<ILoggingEvent> logAppender;

        @BeforeEach
        void rewireWithVerifiableSms() {
            verifiableSms = mock(VerifiableSms.class);
            ReflectionTestUtils.setField(otpController, "smsService", verifiableSms);

            // Attach a Logback ListAppender so the PROVIDER_ERROR /
            // INVALID_CODE branch tests can assert what was actually
            // logged, not just the response body shape.
            otpControllerLogger = (Logger) LoggerFactory.getLogger(OtpController.class);
            logAppender = new ListAppender<>();
            logAppender.start();
            otpControllerLogger.addAppender(logAppender);
        }

        @AfterEach
        void detachAppender() {
            if (otpControllerLogger != null && logAppender != null) {
                otpControllerLogger.detachAppender(logAppender);
                logAppender.stop();
            }
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
        @DisplayName("verify: must delegate to VerifiableSmsService.verifyCodeDetailed, not OtpService.validate")
        void verifyShouldDelegateToProvider() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(verifiableSms.verifyCodeDetailed("+905551234567", "654321"))
                    .thenReturn(VerifiableSmsService.VerifyResult.APPROVED);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "654321"));

            assertThat(response.getBody()).containsEntry("success", true);
            verify(verifiableSms).verifyCodeDetailed("+905551234567", "654321");
            verify(otpService, never()).validate(any(), any());
            verify(otpService, never()).validateWithResult(any(), any());
        }

        @Test
        @DisplayName("verify: rejects when provider says INVALID_CODE — logs reason=INVALID_CODE")
        void verifyRejectsWhenProviderReturnsInvalid() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(verifiableSms.verifyCodeDetailed("+905551234567", "000000"))
                    .thenReturn(VerifiableSmsService.VerifyResult.INVALID_CODE);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "000000"));

            assertThat(response.getBody()).containsEntry("success", false);

            // The branch under test logs a WARN with reason=INVALID_CODE
            // and the message prefix "SMS OTP mismatch". Assert both so a
            // future refactor that collapses the switch back to a single
            // string fails this test.
            assertThat(logAppender.list)
                    .as("OtpController must log SMS OTP mismatch with reason=INVALID_CODE")
                    .anySatisfy(event -> {
                        assertThat(event.getLevel()).isEqualTo(Level.WARN);
                        String formatted = event.getFormattedMessage();
                        assertThat(formatted).contains("SMS OTP mismatch");
                        assertThat(formatted).contains("reason=INVALID_CODE");
                    });
        }

        @Test
        @DisplayName("verify: rejects (logs reason=PROVIDER_ERROR + 'provider error' summary) when provider call errors")
        void verifyRejectsOnProviderError() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(verifiableSms.verifyCodeDetailed("+905551234567", "999999"))
                    .thenReturn(VerifiableSmsService.VerifyResult.PROVIDER_ERROR);

            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", "999999"));

            // Same outward shape (no info leak), but the controller logs
            // reason=PROVIDER_ERROR vs reason=INVALID_CODE for ops triage,
            // and the summary string says "provider error" (not "mismatch")
            // so dashboards filtering on free text don't lump the two.
            assertThat(response.getBody()).containsEntry("success", false);

            assertThat(logAppender.list)
                    .as("OtpController must log SMS OTP provider error with reason=PROVIDER_ERROR")
                    .anySatisfy(event -> {
                        assertThat(event.getLevel()).isEqualTo(Level.WARN);
                        String formatted = event.getFormattedMessage();
                        assertThat(formatted).contains("SMS OTP provider error");
                        assertThat(formatted).contains("reason=PROVIDER_ERROR");
                    });
            // Negative assertion: the misleading "mismatch" wording from
            // the pre-fix code must NOT appear for a provider-error case.
            assertThat(logAppender.list)
                    .noneSatisfy(event -> assertThat(event.getFormattedMessage())
                            .contains("SMS OTP mismatch"));
        }

        @Test
        @DisplayName("verify: strips zero-width / bidi marks from carrier-relayed code (NFKC)")
        void verifyNormalizesUnicodeMarks() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            // Provider only ever sees the cleaned digits.
            when(verifiableSms.verifyCodeDetailed("+905551234567", "654321"))
                    .thenReturn(VerifiableSmsService.VerifyResult.APPROVED);

            // U+200E LEFT-TO-RIGHT MARK + U+FEFF ZWNBSP wrapped around digits,
            // plus surrounding whitespace — the kind of payload Turkish carriers
            // sometimes inject before relaying SMS to RCS clients.
            String dirty = " ‎654321﻿ ";
            ResponseEntity<Map<String, Object>> response =
                    otpController.verifySmsOtp(userId, Map.of("code", dirty));

            assertThat(response.getBody()).containsEntry("success", true);
            verify(verifiableSms).verifyCodeDetailed("+905551234567", "654321");
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
