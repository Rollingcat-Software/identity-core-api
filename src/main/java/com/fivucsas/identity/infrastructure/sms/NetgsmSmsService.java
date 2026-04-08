package com.fivucsas.identity.infrastructure.sms;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * NetGSM SMS service adapter.
 *
 * <p>Uses NetGSM's dedicated OTP endpoint for sending verification codes.
 * Designed for Turkey domestic SMS — significantly cheaper than international
 * providers (~€0.001/SMS vs Twilio's international rates).
 *
 * <p>API docs: https://www.netgsm.com.tr/dokuman/
 *
 * <p>Response codes:
 * <ul>
 *   <li>00 — Success</li>
 *   <li>20 — Invalid message text</li>
 *   <li>30 — Invalid credentials or IP restriction</li>
 *   <li>40 — Message header not defined</li>
 *   <li>50 — Recipient number invalid</li>
 *   <li>60 — Invalid transmission type</li>
 *   <li>70 — Incorrect parameter format</li>
 * </ul>
 */
@Service
@ConditionalOnProperty(name = "sms.provider", havingValue = "netgsm")
@Slf4j
public class NetgsmSmsService implements SmsService {

    private static final String NETGSM_OTP_URL = "https://api.netgsm.com.tr/sms/send/otp";

    @Value("${sms.netgsm.usercode}")
    private String usercode;

    @Value("${sms.netgsm.password}")
    private String password;

    @Value("${sms.netgsm.msgheader}")
    private String msgheader;

    private final RestClient restClient;

    public NetgsmSmsService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    @PostConstruct
    void init() {
        if (usercode == null || usercode.isBlank()) {
            log.warn("NetGSM usercode is empty — SMS sending will fail");
        } else {
            log.info("NetGSM SMS service initialized (header: {})", msgheader);
        }
    }

    @Override
    public void sendOtp(String phoneNumber, String code) {
        String message = String.format(
                "FIVUCSAS dogrulama kodunuz: %s. 5 dakika gecerlidir.", code
        );

        String normalizedPhone = normalizePhoneNumber(phoneNumber);

        String url = NETGSM_OTP_URL
                + "?usercode=" + encode(usercode)
                + "&password=" + encode(password)
                + "&msgheader=" + encode(msgheader)
                + "&msg=" + encode(message)
                + "&no=" + encode(normalizedPhone);

        try {
            String response = restClient.get()
                    .uri(url)
                    .retrieve()
                    .body(String.class);

            if (response != null && response.trim().startsWith("00")) {
                log.info("SMS sent to {} via NetGSM", maskPhone(normalizedPhone));
            } else {
                String errorCode = response != null ? response.trim() : "null";
                log.error("NetGSM error for {}: code={}", maskPhone(normalizedPhone), errorCode);
                throw new RuntimeException("NetGSM SMS delivery failed: " + errorCode);
            }
        } catch (RuntimeException e) {
            if (e.getMessage() != null && e.getMessage().startsWith("NetGSM")) {
                throw e;
            }
            log.error("Failed to send SMS to {} via NetGSM: {}", maskPhone(normalizedPhone), e.getMessage());
            throw new RuntimeException("SMS delivery failed", e);
        }
    }

    /**
     * Normalize phone number to NetGSM format (90XXXXXXXXXX).
     * Accepts: +905551234567, 905551234567, 05551234567, 5551234567
     */
    private String normalizePhoneNumber(String phone) {
        String digits = phone.replaceAll("[^0-9]", "");
        if (digits.startsWith("90") && digits.length() == 12) {
            return digits;
        }
        if (digits.startsWith("0") && digits.length() == 11) {
            return "90" + digits.substring(1);
        }
        if (digits.length() == 10) {
            return "90" + digits;
        }
        return digits;
    }

    private String maskPhone(String phone) {
        if (phone.length() > 6) {
            return phone.substring(0, 4) + "****" + phone.substring(phone.length() - 2);
        }
        return "****";
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
