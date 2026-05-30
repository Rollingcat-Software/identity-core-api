package com.fivucsas.identity.infrastructure.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

@Service
@ConditionalOnProperty(name = "mail.enabled", havingValue = "true")
@Slf4j
public class SmtpEmailService implements EmailService {

    private static final DateTimeFormatter ACCESS_WINDOW_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final String frontendBaseUrl;

    public SmtpEmailService(JavaMailSender mailSender,
                            @Value("${mail.from}") String fromAddress,
                            @Value("${app.frontend-base-url:https://app.fivucsas.com}") String frontendBaseUrl) {
        this.mailSender = mailSender;
        this.fromAddress = fromAddress;
        // Strip a trailing slash so link building stays predictable.
        this.frontendBaseUrl = frontendBaseUrl.endsWith("/")
                ? frontendBaseUrl.substring(0, frontendBaseUrl.length() - 1)
                : frontendBaseUrl;
    }

    @Override
    @Async
    public void sendOtp(String to, String code) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromAddress);
            message.setTo(to);
            message.setSubject("FIVUCSAS - Your verification code");
            message.setText("Your verification code is: " + code + "\n\nThis code expires in 5 minutes.");
            mailSender.send(message);
            log.info("OTP email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send OTP email to: {}", to, e);
        }
    }

    @Override
    @Async
    public void sendGuestInvitation(String to, String token, Instant accessStart, Instant accessEnd,
                                    String message, String inviterName, String tenantName, String locale) {
        try {
            String acceptLink = frontendBaseUrl + "/accept-invite?token="
                    + URLEncoder.encode(token, StandardCharsets.UTF_8);

            boolean tr = isTurkish(locale);
            String org = (tenantName != null && !tenantName.isBlank()) ? tenantName.trim() : null;

            StringBuilder body = new StringBuilder();
            if (tr) {
                buildGuestInvitationBodyTr(body, acceptLink, accessStart, accessEnd, message, inviterName, org);
            } else {
                buildGuestInvitationBodyEn(body, acceptLink, accessStart, accessEnd, message, inviterName, org);
            }

            String subject = tr
                    ? "FIVUCSAS - Misafir olarak davet edildiniz"
                    : "FIVUCSAS - You have been invited as a guest";

            SimpleMailMessage mail = new SimpleMailMessage();
            mail.setFrom(fromAddress);
            mail.setTo(to);
            mail.setSubject(subject);
            mail.setText(body.toString());
            mailSender.send(mail);
            log.info("Guest invitation email sent to: {} (locale={})", to, tr ? "tr" : "en");
        } catch (Exception e) {
            // Never let a mail failure propagate — the caller treats invitation
            // creation as authoritative and the admin can resend.
            log.error("Failed to send guest invitation email to: {}", to, e);
        }
    }

    private void buildGuestInvitationBodyEn(StringBuilder body, String acceptLink,
                                            Instant accessStart, Instant accessEnd,
                                            String message, String inviterName, String org) {
        body.append("Hello,\n\n");
        String target = (org != null) ? org : "FIVUCSAS";
        if (inviterName != null && !inviterName.isBlank()) {
            body.append(inviterName).append(" has invited you to access ").append(target)
                    .append(" as a guest.\n\n");
        } else {
            body.append("You have been invited to access ").append(target).append(" as a guest.\n\n");
        }

        if (accessStart != null && accessEnd != null) {
            body.append("Your access window:\n")
                    .append("  From: ").append(ACCESS_WINDOW_FORMAT.format(accessStart)).append("\n")
                    .append("  Until: ").append(ACCESS_WINDOW_FORMAT.format(accessEnd)).append("\n\n");
        }

        if (message != null && !message.isBlank()) {
            body.append("Message from your host:\n").append(message).append("\n\n");
        }

        body.append("To accept this invitation and create your account, open the link below:\n\n")
                .append(acceptLink).append("\n\n")
                .append("This invitation link will expire. If it has expired, ask the person who invited you ")
                .append("to resend it.\n\n")
                .append("If you were not expecting this invitation, you can safely ignore this email.\n\n")
                .append("— FIVUCSAS");
    }

    private void buildGuestInvitationBodyTr(StringBuilder body, String acceptLink,
                                            Instant accessStart, Instant accessEnd,
                                            String message, String inviterName, String org) {
        body.append("Merhaba,\n\n");
        String target = (org != null) ? org : "FIVUCSAS";
        if (inviterName != null && !inviterName.isBlank()) {
            body.append(inviterName).append(", sizi ").append(target)
                    .append(" platformuna misafir olarak davet etti.\n\n");
        } else {
            body.append(target).append(" platformuna misafir olarak davet edildiniz.\n\n");
        }

        if (accessStart != null && accessEnd != null) {
            body.append("Erişim süreniz:\n")
                    .append("  Başlangıç: ").append(ACCESS_WINDOW_FORMAT.format(accessStart)).append("\n")
                    .append("  Bitiş: ").append(ACCESS_WINDOW_FORMAT.format(accessEnd)).append("\n\n");
        }

        if (message != null && !message.isBlank()) {
            body.append("Sizi davet eden kişiden mesaj:\n").append(message).append("\n\n");
        }

        body.append("Bu daveti kabul edip hesabınızı oluşturmak için aşağıdaki bağlantıyı açın:\n\n")
                .append(acceptLink).append("\n\n")
                .append("Bu davet bağlantısının süresi dolacaktır. Süresi dolduysa sizi davet eden kişiden ")
                .append("yeniden göndermesini isteyin.\n\n")
                .append("Bu daveti beklemiyorsanız, bu e-postayı güvenle yok sayabilirsiniz.\n\n")
                .append("— FIVUCSAS");
    }

    private static boolean isTurkish(String locale) {
        if (locale == null || locale.isBlank()) {
            return false;
        }
        return locale.trim().toLowerCase().startsWith("tr");
    }

    @Override
    @Async
    public void sendTenantOnboardingVerification(String to, String adminName, String orgName, String token) {
        try {
            String verifyLink = frontendBaseUrl + "/verify-email?token="
                    + URLEncoder.encode(token, StandardCharsets.UTF_8);

            StringBuilder body = new StringBuilder();
            if (adminName != null && !adminName.isBlank()) {
                body.append("Hello ").append(adminName).append(",\n\n");
            } else {
                body.append("Hello,\n\n");
            }
            body.append("Thanks for registering '").append(orgName)
                    .append("' on FIVUCSAS.\n\n")
                    .append("Verify your email to activate your organisation and finish setting up "
                            + "your administrator account. Open the link below:\n\n")
                    .append(verifyLink).append("\n\n")
                    .append("This link expires in 24 hours. If you did not request this, you can ")
                    .append("safely ignore this email.\n\n")
                    .append("— FIVUCSAS");

            SimpleMailMessage mail = new SimpleMailMessage();
            mail.setFrom(fromAddress);
            mail.setTo(to);
            mail.setSubject("FIVUCSAS - Verify your email to activate " + orgName);
            mail.setText(body.toString());
            mailSender.send(mail);
            log.info("Tenant onboarding verification email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send tenant onboarding verification email to: {}", to, e);
        }
    }
}
