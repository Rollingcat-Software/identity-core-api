package com.fivucsas.identity.infrastructure.email;

import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
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

    /** Brand colour for the wordmark / accent (matches the web dashboard). */
    private static final String BRAND_COLOR = "#6366f1";

    /** OTP validity, in minutes, surfaced in the expiry note. Mirrors OtpService.OTP_TTL. */
    private static final int OTP_TTL_MINUTES = 5;

    @Override
    @Async
    public void sendOtp(String to, String code) {
        sendOtp(to, code, OtpPurpose.LOGIN_VERIFICATION, null);
    }

    @Override
    @Async
    public void sendOtp(String to, String code, OtpPurpose purpose, String locale) {
        OtpPurpose resolvedPurpose = (purpose != null) ? purpose : OtpPurpose.LOGIN_VERIFICATION;
        boolean tr = isTurkish(locale);

        OtpCopy copy = otpCopy(resolvedPurpose, tr);
        String subject = copy.subject;
        String html = buildOtpHtml(code, copy);
        String plainText = buildOtpPlainText(code, copy);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            // multipart=true → a multipart/alternative body so we can attach BOTH
            // the plain-text fallback and the HTML part via setText(plain, html).
            MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(fromAddress);
            helper.setTo(to);
            helper.setSubject(subject);
            // Plain text first, HTML second → multipart/alternative with the
            // HTML body preferred, the plain text shown as a fallback.
            helper.setText(plainText, html);
            mailSender.send(message);
            log.info("OTP email sent to: {} (purpose={}, locale={})", to, resolvedPurpose, tr ? "tr" : "en");
        } catch (Exception e) {
            log.error("Failed to send OTP email to: {} (purpose={})", to, resolvedPurpose, e);
        }
    }

    /**
     * Localized, purpose-specific strings for the OTP email. Kept tiny and
     * inline (no templating engine / extra dependency) — the layout is shared,
     * only the wording changes per purpose + language.
     */
    private record OtpCopy(String subject, String heading, String intro,
                           String codeLabel, String expiry, String ignore) {
    }

    private OtpCopy otpCopy(OtpPurpose purpose, boolean tr) {
        String expiry = tr
                ? "Bu kod " + OTP_TTL_MINUTES + " dakika içinde geçerliliğini yitirir."
                : "This code expires in " + OTP_TTL_MINUTES + " minutes.";
        String ignore = tr
                ? "Bu kodu siz istemediyseniz, bu e-postayı güvenle yok sayabilirsiniz."
                : "If you did not request this code, you can safely ignore this email.";
        String codeLabel = tr ? "Doğrulama kodunuz" : "Your verification code";

        return switch (purpose) {
            case PASSWORD_RESET -> tr
                    ? new OtpCopy(
                        "FIVUCSAS - Parola sıfırlama kodunuz",
                        "Parola sıfırlama",
                        "Parolanızı sıfırlamak için aşağıdaki kodu kullanın.",
                        "Parola sıfırlama kodunuz",
                        expiry,
                        "Parola sıfırlama talebinde bulunmadıysanız, bu e-postayı yok sayın; "
                                + "parolanız değişmeden kalır.")
                    : new OtpCopy(
                        "FIVUCSAS - Your password reset code",
                        "Password reset",
                        "Use the code below to reset your password.",
                        "Your password reset code",
                        expiry,
                        "If you did not request a password reset, ignore this email; "
                                + "your password stays unchanged.");
            case EMAIL_VERIFICATION -> tr
                    ? new OtpCopy(
                        "FIVUCSAS - E-posta doğrulama kodunuz",
                        "E-postanızı doğrulayın",
                        "Hesabınızı etkinleştirmek için e-posta adresinizi aşağıdaki kodla doğrulayın.",
                        "E-posta doğrulama kodunuz",
                        expiry,
                        ignore)
                    : new OtpCopy(
                        "FIVUCSAS - Verify your email",
                        "Verify your email",
                        "Confirm your email address with the code below to activate your account.",
                        "Your email verification code",
                        expiry,
                        ignore);
            case ACCOUNT_LINK -> tr
                    ? new OtpCopy(
                        "FIVUCSAS - Hesap bağlama kodunuz",
                        "Hesap bağlama",
                        "Bu e-posta adresinin sahibi olduğunuzu doğrulamak için aşağıdaki kodu kullanın.",
                        "Hesap bağlama kodunuz",
                        expiry,
                        "Bu hesabı bağlama talebinde bulunmadıysanız, bu e-postayı güvenle yok sayabilirsiniz.")
                    : new OtpCopy(
                        "FIVUCSAS - Your account link code",
                        "Link your account",
                        "Use the code below to confirm you own this email address.",
                        "Your account link code",
                        expiry,
                        "If you did not request to link this account, you can safely ignore this email.");
            case LOGIN_VERIFICATION -> tr
                    ? new OtpCopy(
                        "FIVUCSAS - Doğrulama kodunuz",
                        "Giriş doğrulama",
                        "Girişinizi tamamlamak için aşağıdaki doğrulama kodunu kullanın.",
                        codeLabel,
                        expiry,
                        ignore)
                    : new OtpCopy(
                        "FIVUCSAS - Your verification code",
                        "Sign-in verification",
                        "Use the verification code below to complete your sign-in.",
                        codeLabel,
                        expiry,
                        ignore);
        };
    }

    /**
     * Inline-styled HTML body. Self-contained (no external CSS / images) so it
     * renders consistently across email clients. The code is shown prominently
     * with wide letter-spacing for easy reading.
     */
    private String buildOtpHtml(String code, OtpCopy copy) {
        return "<!DOCTYPE html>"
                + "<html><body style=\"margin:0;padding:0;background:#f3f4f6;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" "
                +   "style=\"background:#f3f4f6;padding:24px 0;\"><tr><td align=\"center\">"
                + "<table role=\"presentation\" width=\"480\" cellpadding=\"0\" cellspacing=\"0\" "
                +   "style=\"max-width:480px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;"
                +   "font-family:Arial,Helvetica,sans-serif;box-shadow:0 1px 3px rgba(0,0,0,0.08);\">"
                // Header / wordmark
                + "<tr><td style=\"background:" + BRAND_COLOR + ";padding:24px 32px;\">"
                +   "<span style=\"color:#ffffff;font-size:22px;font-weight:bold;letter-spacing:1px;\">"
                +   "FIVUCSAS</span></td></tr>"
                // Body
                + "<tr><td style=\"padding:32px;color:#1f2937;\">"
                +   "<h1 style=\"margin:0 0 16px;font-size:20px;color:#111827;\">"
                +     escape(copy.heading) + "</h1>"
                +   "<p style=\"margin:0 0 24px;font-size:15px;line-height:1.6;color:#374151;\">"
                +     escape(copy.intro) + "</p>"
                +   "<p style=\"margin:0 0 8px;font-size:13px;color:#6b7280;\">"
                +     escape(copy.codeLabel) + "</p>"
                +   "<div style=\"font-size:34px;font-weight:bold;letter-spacing:8px;color:" + BRAND_COLOR + ";"
                +     "background:#f5f3ff;border-radius:8px;padding:16px;text-align:center;margin:0 0 24px;\">"
                +     escape(code) + "</div>"
                +   "<p style=\"margin:0;font-size:13px;color:#6b7280;\">" + escape(copy.expiry) + "</p>"
                + "</td></tr>"
                // Footer
                + "<tr><td style=\"padding:20px 32px;background:#f9fafb;border-top:1px solid #e5e7eb;\">"
                +   "<p style=\"margin:0 0 4px;font-size:12px;color:#9ca3af;\">" + escape(copy.ignore) + "</p>"
                +   "<p style=\"margin:0;font-size:12px;color:#9ca3af;\">&copy; 2026 FIVUCSAS</p>"
                + "</td></tr>"
                + "</table></td></tr></table></body></html>";
    }

    /** Plain-text fallback for clients that cannot render HTML. */
    private String buildOtpPlainText(String code, OtpCopy copy) {
        return copy.heading + "\n\n"
                + copy.intro + "\n\n"
                + copy.codeLabel + ": " + code + "\n\n"
                + copy.expiry + "\n\n"
                + copy.ignore + "\n\n"
                + "— FIVUCSAS";
    }

    /** Minimal HTML escaping for the dynamic strings interpolated into the body. */
    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
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
