package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@Slf4j
public class NfcDocumentAuthHandler implements AuthMethodHandler {

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.NFC_DOCUMENT;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String nfcData = (String) data.get("nfcData");

        if (nfcData == null || nfcData.isEmpty()) {
            return StepResult.failure(
                    "NFC document scanning requires physical NFC hardware. " +
                    "This authentication method is only available on devices with NFC readers.");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before NFC document verification");
        }

        // NFC document verification is a stub - requires physical hardware integration.
        // In production, this would validate the NFC chip data against stored document hashes.
        log.warn("NFC document authentication attempted for session: {} - hardware integration pending",
                session.getId());
        return StepResult.failure(
                "NFC document verification is not yet available. " +
                "Physical NFC reader hardware integration is pending.");
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("nfcData");
    }
}
