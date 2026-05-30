package com.fivucsas.identity.infrastructure.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("SmtpEmailService.sendGuestInvitation — EN/TR localization")
class SmtpEmailServiceGuestInvitationTest {

    @Mock private JavaMailSender mailSender;

    private SmtpEmailService service;

    @BeforeEach
    void setUp() {
        service = new SmtpEmailService(mailSender, "info@fivucsas.com", "https://app.fivucsas.com/");
    }

    private SimpleMailMessage capture() {
        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(captor.capture());
        return captor.getValue();
    }

    @Test
    @DisplayName("locale 'tr' → Turkish subject + body, with tenant name + accept link")
    void turkishBody() {
        Instant start = Instant.parse("2026-06-01T10:00:00Z");
        Instant end = Instant.parse("2026-06-02T10:00:00Z");

        service.sendGuestInvitation("guest@example.com", "TOK123", start, end,
                "Hoş geldiniz", "Yönetici", "Marmara Üniversitesi", "tr");

        SimpleMailMessage mail = capture();
        assertThat(mail.getFrom()).isEqualTo("info@fivucsas.com");
        assertThat(mail.getSubject()).contains("Misafir olarak davet edildiniz");
        String body = String.join("", mail.getText());
        assertThat(body).contains("Merhaba");
        assertThat(body).contains("Marmara Üniversitesi");
        assertThat(body).contains("Erişim süreniz");
        assertThat(body).contains("https://app.fivucsas.com/accept-invite?token=TOK123");
    }

    @Test
    @DisplayName("locale 'en' → English subject + body")
    void englishBody() {
        service.sendGuestInvitation("guest@example.com", "TOK123", null, null,
                null, "Admin", "Acme Corp", "en");

        SimpleMailMessage mail = capture();
        assertThat(mail.getSubject()).contains("invited as a guest");
        String body = String.join("", mail.getText());
        assertThat(body).contains("Hello,");
        assertThat(body).contains("Acme Corp");
        assertThat(body).contains("accept-invite?token=TOK123");
    }

    @Test
    @DisplayName("null/unknown locale falls back to English")
    void nullLocaleFallsBackEnglish() {
        service.sendGuestInvitation("guest@example.com", "TOK123", null, null,
                null, null, "Acme Corp", null);

        SimpleMailMessage mail = capture();
        assertThat(mail.getSubject()).contains("invited as a guest");
        assertThat(String.join("", mail.getText())).contains("Hello,");
    }

    @Test
    @DisplayName("blank tenant name → falls back to 'FIVUCSAS' in the body")
    void blankTenantNameFallsBack() {
        service.sendGuestInvitation("guest@example.com", "TOK123", null, null,
                null, null, "  ", "en");

        String body = String.join("", capture().getText());
        assertThat(body).contains("FIVUCSAS as a guest");
    }
}
