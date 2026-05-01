package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
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
public class NfcDocumentVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final NfcCardRepositoryPort nfcCardRepository;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.NFC_DOCUMENT;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String nfcData = (String) data.get("nfcData");
        if (nfcData == null || nfcData.isBlank()) {
            return MfaStepResult.fail();
        }
        boolean ok = nfcCardRepository
                .findByCardSerialAndUserIdAndIsActiveTrue(nfcData, user.getId())
                .isPresent();
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
