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
                                    String message, String inviterName) {
        try {
            String acceptLink = frontendBaseUrl + "/accept-invite?token="
                    + URLEncoder.encode(token, StandardCharsets.UTF_8);

            StringBuilder body = new StringBuilder();
            body.append("Hello,\n\n");
            if (inviterName != null && !inviterName.isBlank()) {
                body.append(inviterName).append(" has invited you to access FIVUCSAS as a guest.\n\n");
            } else {
                body.append("You have been invited to access FIVUCSAS as a guest.\n\n");
            }

            if (accessStart != null && accessEnd != null) {
                body.append("Your access window:\n")
                        .append("  From: ").append(ACCESS_WINDOW_FORMAT.format(accessStart)).append("\n")
                        .append("  Until: ").append(ACCESS_WINDOW_FORMAT.format(accessEnd)).append("\n\n");
            }

            if (message != null && !message.isBlank()) {
                body.append("Message from your host:\n")
                        .append(message).append("\n\n");
            }

            body.append("To accept this invitation and create your account, open the link below:\n\n")
                    .append(acceptLink).append("\n\n")
                    .append("This invitation link will expire. If it has expired, ask the person who invited you ")
                    .append("to resend it.\n\n")
                    .append("If you were not expecting this invitation, you can safely ignore this email.\n\n")
                    .append("— FIVUCSAS");

            SimpleMailMessage mail = new SimpleMailMessage();
            mail.setFrom(fromAddress);
            mail.setTo(to);
            mail.setSubject("FIVUCSAS - You have been invited as a guest");
            mail.setText(body.toString());
            mailSender.send(mail);
            log.info("Guest invitation email sent to: {}", to);
        } catch (Exception e) {
            // Never let a mail failure propagate — the caller treats invitation
            // creation as authoritative and the admin can resend.
            log.error("Failed to send guest invitation email to: {}", to, e);
        }
    }
}
