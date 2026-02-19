package com.fivucsas.identity.infrastructure.sms;

public interface SmsService {
    void sendOtp(String phoneNumber, String code);
}
