package com.fivucsas.identity.infrastructure.email;

import jakarta.mail.Part;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies the branded, bilingual, purpose-aware OTP email body. The OTP mail
 * is now a {@link MimeMessage} (HTML + plain-text fallback) — these tests
 * capture the sent MimeMessage and assert on its rendered content.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SmtpEmailService.sendOtp — branded bilingual OTP/reset email")
class SmtpEmailServiceOtpTest {

    @Mock private JavaMailSender mailSender;

    private SmtpEmailService service;

    @BeforeEach
    void setUp() {
        service = new SmtpEmailService(mailSender, "info@fivucsas.com", "https://app.fivucsas.com");
        // createMimeMessage() must return a real, writable MimeMessage so the
        // MimeMessageHelper can populate it. JavaMailSenderImpl gives us one
        // backed by a default Session without any SMTP connection.
        when(mailSender.createMimeMessage())
                .thenReturn(new JavaMailSenderImpl().createMimeMessage());
    }

    /** Captures the single sent MimeMessage. */
    private MimeMessage captured() {
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        return captor.getValue();
    }

    /**
     * Returns the DECODED text of every leaf MIME part (plain-text fallback +
     * HTML) concatenated, so assertions match the human-readable body
     * regardless of the quoted-printable transfer encoding used on the wire.
     * Recurses through the multipart/mixed → multipart/alternative nesting that
     * {@link org.springframework.mail.javamail.MimeMessageHelper} produces.
     */
    private String captureRendered() throws Exception {
        StringBuilder sb = new StringBuilder();
        collectText(captured().getContent(), sb);
        return sb.toString();
    }

    private void collectText(Object content, StringBuilder sb) throws Exception {
        if (content instanceof MimeMultipart multipart) {
            for (int i = 0; i < multipart.getCount(); i++) {
                Part part = multipart.getBodyPart(i);
                collectText(part.getContent(), sb);
            }
        } else if (content instanceof String text) {
            sb.append(text).append("\n");
        }
    }

    private String subject() throws Exception {
        return captured().getSubject();
    }

    @Test
    @DisplayName("legacy sendOtp(to, code) → English login-verification, branded HTML")
    void legacyOverloadIsBrandedLoginVerification() throws Exception {
        service.sendOtp("user@example.com", "123456");

        assertThat(subject()).isEqualTo("FIVUCSAS - Your verification code");
        String body = captureRendered();
        assertThat(body).contains("FIVUCSAS");          // wordmark header
        assertThat(body).contains("#6366f1");           // brand colour
        assertThat(body).contains("123456");            // the code, prominently
        assertThat(body).contains("Your verification code");
        assertThat(body).contains("expires in 5 minutes");
        // HTML body present (multipart/alternative with an HTML part)
        assertThat(body).contains("<!DOCTYPE html>");
    }

    @Test
    @DisplayName("password-reset purpose → 'password reset code' copy, NOT 'verification code' subject")
    void passwordResetIsClearlyLabeled() throws Exception {
        service.sendOtp("user@example.com", "987654", OtpPurpose.PASSWORD_RESET, "en");

        assertThat(subject()).isEqualTo("FIVUCSAS - Your password reset code");
        String body = captureRendered();
        assertThat(body).contains("987654");
        assertThat(body).contains("Your password reset code");
        assertThat(body).contains("reset your password");
        // It must NOT masquerade as a generic verification code.
        assertThat(subject()).doesNotContain("verification code");
    }

    @Test
    @DisplayName("Turkish locale → Turkish subject + body")
    void turkishLoginVerification() throws Exception {
        service.sendOtp("user@example.com", "111222", OtpPurpose.LOGIN_VERIFICATION, "tr");

        assertThat(subject()).contains("Doğrulama kodunuz");
        String body = captureRendered();
        assertThat(body).contains("111222");
        assertThat(body).contains("Giriş doğrulama");
        assertThat(body).contains("dakika"); // expiry note in TR
    }

    @Test
    @DisplayName("Turkish password reset → Turkish reset copy")
    void turkishPasswordReset() throws Exception {
        service.sendOtp("user@example.com", "333444", OtpPurpose.PASSWORD_RESET, "tr");

        assertThat(subject()).contains("Parola sıfırlama kodunuz");
        String body = captureRendered();
        assertThat(body).contains("333444");
        assertThat(body).contains("Parola sıfırlama");
    }

    @Test
    @DisplayName("email-verification purpose → registration copy")
    void emailVerification() throws Exception {
        service.sendOtp("new@example.com", "555666", OtpPurpose.EMAIL_VERIFICATION, "en");

        assertThat(subject()).isEqualTo("FIVUCSAS - Verify your email");
        String body = captureRendered();
        assertThat(body).contains("555666");
        assertThat(body).contains("Verify your email");
        assertThat(body).contains("activate your account");
    }

    @Test
    @DisplayName("account-link purpose → link copy")
    void accountLink() throws Exception {
        service.sendOtp("link@example.com", "777888", OtpPurpose.ACCOUNT_LINK, "en");

        assertThat(subject()).isEqualTo("FIVUCSAS - Your account link code");
        String body = captureRendered();
        assertThat(body).contains("777888");
        assertThat(body).contains("Link your account");
    }

    @Test
    @DisplayName("null purpose / null locale → English login-verification fallback")
    void nullPurposeFallsBackToEnglishLoginVerification() throws Exception {
        service.sendOtp("user@example.com", "999000", null, null);

        assertThat(subject()).isEqualTo("FIVUCSAS - Your verification code");
        assertThat(captureRendered()).contains("Your verification code");
    }
}
