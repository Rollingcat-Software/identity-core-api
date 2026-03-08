package com.fivucsas.identity.infrastructure.adapter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.Map;

/**
 * Adapter for sending emails using JavaMailSender and Thymeleaf templates.
 * Sends emails asynchronously to avoid blocking application threads.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class EmailServiceAdapter {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${spring.mail.from:noreply@fivucsas.com}")
    private String fromEmail;

    @Value("${app.url:http://localhost:3000}")
    private String appUrl;

    /**
     * Sends password reset email.
     */
    @Async
    public void sendPasswordResetEmail(String toEmail, String resetToken) {
        String resetLink = appUrl + "/reset-password?token=" + resetToken;

        Context context = new Context();
        context.setVariable("resetLink", resetLink);
        context.setVariable("expiresIn", "1 hour");

        sendTemplateEmail(toEmail, "Password Reset Request", "email/password-reset", context);
    }

    /**
     * Sends welcome email to new users.
     */
    @Async
    public void sendWelcomeEmail(String toEmail, String userName) {
        Context context = new Context();
        context.setVariable("userName", userName);
        context.setVariable("loginLink", appUrl + "/login");

        sendTemplateEmail(toEmail, "Welcome to FIVUCSAS", "email/welcome", context);
    }

    /**
     * Sends login alert email.
     */
    @Async
    public void sendLoginAlertEmail(String toEmail, String userName, String ipAddress) {
        Context context = new Context();
        context.setVariable("userName", userName);
        context.setVariable("ipAddress", ipAddress);
        context.setVariable("timestamp", java.time.Instant.now().toString());

        sendTemplateEmail(toEmail, "New Login Detected", "email/login-alert", context);
    }

    private void sendTemplateEmail(String to, String subject, String templateName, Context context) {
        try {
            String htmlContent = templateEngine.process(templateName, context);
            sendHtmlEmail(to, subject, htmlContent);
            log.info("Email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage(), e);
        }
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(fromEmail);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }
}
