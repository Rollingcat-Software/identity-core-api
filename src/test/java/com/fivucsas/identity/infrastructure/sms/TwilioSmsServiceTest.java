package com.fivucsas.identity.infrastructure.sms;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@DisplayName("SMS Service Configuration Tests")
class SmsServiceConfigTest {

    private final NoOpSmsService noOpSmsService = new NoOpSmsService();

    @Test
    @DisplayName("NoOp SMS service should be an instance of SmsService")
    void noOpSmsService_WhenSmsDisabled_ShouldBeActive() {
        assertThat(noOpSmsService).isInstanceOf(SmsService.class);
    }

    @Test
    @DisplayName("NoOp SMS service should log OTP without throwing")
    void noOpSmsService_WhenSendOtp_ShouldNotThrow() {
        assertThatCode(() -> noOpSmsService.sendOtp("+905551234567", "123456"))
                .doesNotThrowAnyException();
    }
}
