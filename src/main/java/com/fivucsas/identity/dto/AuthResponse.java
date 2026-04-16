package com.fivucsas.identity.dto;

import com.fivucsas.identity.application.dto.response.UserResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;
    private UserResponse user;

    // --- MFA fields ---

    @Builder.Default
    private boolean mfaRequired = false;

    /** Backward-compat alias for mfaRequired */
    @Builder.Default
    private boolean twoFactorRequired = false;

    /** Primary/preferred method (backward compat for old clients) */
    private String twoFactorMethod;

    /** MFA session token for step-by-step verification. Null when mfaRequired is false. */
    private String mfaSessionToken;

    /** Total number of auth steps in the flow */
    private Integer totalSteps;

    /** Current step number to complete (1-based) */
    private Integer currentStep;

    /** Available methods for the current step (for CHOICE steps). Null for single-factor. */
    private List<AvailableMfaMethod> availableMethods;

    /** Methods already completed in this MFA session (canonical AuthMethodType names). Null for single-factor. */
    private List<String> completedMethods;

    // --- Factory methods ---

    public static AuthResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .user(user)
                .build();
    }

    /** Backward-compatible: single twoFactorMethod */
    public static AuthResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user,
                                  boolean twoFactorRequired, String twoFactorMethod) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .user(user)
                .twoFactorRequired(twoFactorRequired)
                .mfaRequired(twoFactorRequired)
                .twoFactorMethod(twoFactorMethod)
                .build();
    }

    /** New: multi-method MFA with session token */
    public static AuthResponse ofMfa(String accessToken, String refreshToken, Long expiresIn, UserResponse user,
                                     String mfaSessionToken, int totalSteps, int currentStep,
                                     String primaryMethod, List<AvailableMfaMethod> availableMethods,
                                     List<String> completedMethods) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .user(user)
                .mfaRequired(true)
                .twoFactorRequired(true)
                .twoFactorMethod(primaryMethod)
                .mfaSessionToken(mfaSessionToken)
                .totalSteps(totalSteps)
                .currentStep(currentStep)
                .availableMethods(availableMethods)
                .completedMethods(completedMethods)
                .build();
    }
}
