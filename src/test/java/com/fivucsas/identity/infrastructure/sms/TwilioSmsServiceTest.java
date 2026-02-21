package com.fivucsas.identity.infrastructure.sms;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("dev")
@DisplayName("SMS Service Configuration Tests")
class SmsServiceConfigTest {

    @Autowired
    private SmsService smsService;

    @Test
    @DisplayName("NoOp SMS service should be active when sms.enabled is false")
    void noOpSmsService_WhenSmsDisabled_ShouldBeActive() {
        assertThat(smsService).isInstanceOf(NoOpSmsService.class);
    }

    @Test
    @DisplayName("NoOp SMS service should log OTP without throwing")
    void noOpSmsService_WhenSendOtp_ShouldNotThrow() {
        smsService.sendOtp("+905551234567", "123456");
        // Should not throw - NoOp just logs
    }
}
