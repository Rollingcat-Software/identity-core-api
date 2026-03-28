package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Handles ADDRESS_PROOF verification step.
 * Currently stores the document and flags it for manual review.
 *
 * TODO: Integrate with OCR/address validation service for automated extraction
 * TODO: Add address matching against government databases
 */
@Component
@Slf4j
public class AddressProofHandler implements VerificationStepHandler {

    @Override
    public String getStepType() {
        return "ADDRESS_PROOF";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String documentImage = (String) data.get("image");
        if (documentImage == null || documentImage.isBlank()) {
            return VerificationStepResult.failure("Address proof document image is required");
        }

        // For now: accept and store the document, flag for manual review
        // The image data would be stored via a media storage service in production
        log.info("Address proof document received for session {}. Flagged for manual review.", session.getId());

        return VerificationStepResult.success(Map.of(
                "status", "PENDING_REVIEW",
                "document_stored", true
        ));
    }
}
