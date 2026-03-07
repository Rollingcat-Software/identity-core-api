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
                    "This authentication method is only available on mobile devices with NFC readers.");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before NFC document verification");
        }

        // NFC document verification requires physical NFC reader hardware integration.
        // In production, this would:
        // 1. Read NFC chip data from the ID document (MRTD/ICAO standard)
        // 2. Verify BAC/PACE authentication
        // 3. Validate document certificate chain
        // 4. Extract and verify biometric data from EF.DG2
        // 5. Compare against stored document hashes
        //
        // See TODO.md AUTH-1 and ROADMAP.md Phase 1 for implementation plans.
        // This method should NOT be configured as a required step until hardware integration is complete.
        log.warn("NFC document authentication attempted for session: {} - hardware integration pending. " +
                "This auth method should not be configured as a required step.", session.getId());
        return StepResult.failure(
                "NFC document verification is not yet available. " +
                "This method requires a mobile device with NFC reader hardware. " +
                "Please contact your administrator to use an alternative authentication method.");
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
