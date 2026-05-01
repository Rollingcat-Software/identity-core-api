package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class VoiceVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final BiometricServicePort biometricService;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.VOICE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String voiceData = (String) data.get("voiceData");
        if (voiceData == null || voiceData.isBlank()) {
            return MfaStepResult.fail();
        }
        Map<String, Object> result = biometricService.verifyVoice(user.getId(), voiceData);
        return Boolean.TRUE.equals(result.get("verified"))
                ? MfaStepResult.ok()
                : MfaStepResult.fail();
    }
}
