package com.fivucsas.identity.infrastructure.sms;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "sms.enabled", havingValue = "true")
@Slf4j
public class TwilioSmsService implements SmsService {

    @Value("${sms.twilio.account-sid}")
    private String accountSid;

    @Value("${sms.twilio.auth-token}")
    private String authToken;

    @Value("${sms.twilio.from-number}")
    private String fromNumber;

    @PostConstruct
    void init() {
        Twilio.init(accountSid, authToken);
        log.info("Twilio SMS service initialized with from-number: {}", fromNumber);
    }

    @Override
    public void sendOtp(String phoneNumber, String code) {
        try {
            Message message = Message.creator(
                    new PhoneNumber(phoneNumber),
                    new PhoneNumber(fromNumber),
                    String.format("Your FIVUCSAS verification code is: %s. Valid for 5 minutes.", code)
            ).create();

            log.info("SMS sent to {} - SID: {}", phoneNumber, message.getSid());
        } catch (Exception e) {
            log.error("Failed to send SMS to {}: {}", phoneNumber, e.getMessage());
            throw new RuntimeException("SMS delivery failed", e);
        }
    }
}
