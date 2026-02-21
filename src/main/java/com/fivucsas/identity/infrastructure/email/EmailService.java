package com.fivucsas.identity.infrastructure.email;

public interface EmailService {
    void sendOtp(String to, String code);
}
