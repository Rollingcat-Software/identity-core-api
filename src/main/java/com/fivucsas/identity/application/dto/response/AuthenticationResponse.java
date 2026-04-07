package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.dto.AvailableMfaMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response for authentication operations (login, register, refresh).
 * Supports both legacy single-method 2FA and new adaptive multi-step MFA.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    private String accessToken;
    private String refreshToken;
    private Long expiresIn;
    private UserResponse user;

    // Legacy 2FA fields (backward compat)
    private boolean twoFactorRequired;
    private String twoFactorMethod;

    // Adaptive MFA fields
    private boolean mfaRequired;
    private String mfaSessionToken;
    private Integer totalSteps;
    private Integer currentStep;
    private List<AvailableMfaMethod> availableMethods;

    /** Single-factor login (no MFA) */
    public static AuthenticationResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(expiresIn)
            .user(user)
            .twoFactorRequired(false)
            .mfaRequired(false)
            .build();
    }

    /** Legacy: single twoFactorMethod */
    public static AuthenticationResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user,
                                            boolean twoFactorRequired, String twoFactorMethod) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(expiresIn)
            .user(user)
            .twoFactorRequired(twoFactorRequired)
            .mfaRequired(twoFactorRequired)
            .twoFactorMethod(twoFactorMethod)
            .build();
    }

    /** Adaptive MFA: multi-step with session token and available methods */
    public static AuthenticationResponse ofMfa(String accessToken, String refreshToken, Long expiresIn, UserResponse user,
                                               String mfaSessionToken, int totalSteps, int currentStep,
                                               String primaryMethod, List<AvailableMfaMethod> availableMethods) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(expiresIn)
            .user(user)
            .twoFactorRequired(true)
            .mfaRequired(true)
            .twoFactorMethod(primaryMethod)
            .mfaSessionToken(mfaSessionToken)
            .totalSteps(totalSteps)
            .currentStep(currentStep)
            .availableMethods(availableMethods)
            .build();
    }

    /** MFA pending: NO tokens issued, only session token + step info. JWT comes after all steps complete. */
    public static AuthenticationResponse ofMfaPending(String mfaSessionToken, int totalSteps, int currentStep,
                                                       String primaryMethod, List<AvailableMfaMethod> availableMethods,
                                                       UserResponse user) {
        return AuthenticationResponse.builder()
            .accessToken(null)
            .refreshToken(null)
            .expiresIn(null)
            .user(user)
            .twoFactorRequired(true)
            .mfaRequired(true)
            .twoFactorMethod(primaryMethod)
            .mfaSessionToken(mfaSessionToken)
            .totalSteps(totalSteps)
            .currentStep(currentStep)
            .availableMethods(availableMethods)
            .build();
    }
}
