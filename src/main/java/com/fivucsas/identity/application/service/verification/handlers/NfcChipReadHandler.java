package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles NFC_CHIP_READ verification step.
 * Accepts NFC data already read by the mobile client and validates/stores it.
 */
@Component
@Slf4j
public class NfcChipReadHandler implements VerificationStepHandler {

    @Override
    public String getStepType() {
        return "NFC_CHIP_READ";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String mrzData = (String) data.get("mrz_data");
        String documentNumber = (String) data.get("document_number");
        String holderName = (String) data.get("holder_name");
        String dateOfBirth = (String) data.get("date_of_birth");

        if (mrzData == null || mrzData.isBlank()) {
            return VerificationStepResult.failure("MRZ data is required from NFC chip read");
        }
        if (documentNumber == null || documentNumber.isBlank()) {
            return VerificationStepResult.failure("Document number is required from NFC chip read");
        }

        // Validate MRZ format (basic check: should contain '<' separators and be at least 30 chars)
        if (mrzData.length() < 30 || !mrzData.contains("<")) {
            return VerificationStepResult.failure("Invalid MRZ data format");
        }

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("mrz_data", mrzData);
        resultData.put("document_number", documentNumber);
        resultData.put("holder_name", holderName != null ? holderName : "");
        resultData.put("date_of_birth", dateOfBirth != null ? dateOfBirth : "");
        resultData.put("nfc_read_success", true);

        log.info("NFC chip read completed for session {}: doc={}", session.getId(), documentNumber);
        return VerificationStepResult.success(1.0, resultData);
    }
}
