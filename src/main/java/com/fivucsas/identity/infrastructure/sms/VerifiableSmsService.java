package com.fivucsas.identity.infrastructure.sms;

/**
 * Extended SMS service that supports native code verification
 * (e.g. Twilio Verify), bypassing the local OTP Redis store.
 */
public interface VerifiableSmsService {
    /**
     * Verifies the OTP code entered by the user directly with the provider.
     *
     * @param phoneNumber E.164 format phone number
     * @param code        Code entered by the user
     * @return true if the code is valid and approved
     */
    boolean verifyCode(String phoneNumber, String code);
}
