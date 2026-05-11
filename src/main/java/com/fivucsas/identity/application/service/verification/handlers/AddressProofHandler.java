package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Handles ADDRESS_PROOF verification step.
 *
 * <p><b>STUB IMPLEMENTATION — gated to dev profile only.</b> Real KYC/AML provider
 * (Refinitiv / Dow Jones / OCR-and-address-validation / S3-backed media storage / etc.)
 * integration is Phase 4 scope. Loading this bean under {@code prod} = bug — the
 * {@code @Profile("dev")} annotation below is the production safety ratchet. If you
 * are looking at this class because something exploded at boot under {@code prod},
 * the answer is NOT to remove the annotation; the answer is to ship a real impl.
 *
 * <p>The current implementation accepts any non-empty
 * image payload and returns {@code status=PENDING_REVIEW, document_stored=true}
 * without actually persisting the image, validating the document, or extracting
 * the address. The inline comment ("would be stored via a media storage service
 * in production") admits as much. Returning a hard-coded "stored" verdict in
 * production would silently false-pass any KYC flow that includes an
 * {@code ADDRESS_PROOF} step.
 *
 * <p>To make the silent-mock-in-prod failure mode impossible, this bean is
 * gated to the {@code dev} Spring profile only. In any non-dev profile (notably
 * {@code prod}) the bean is NOT registered, and
 * {@code VerificationStepHandlerRegistry.getHandler("ADDRESS_PROOF")} will
 * throw {@link UnsupportedOperationException} — surfacing an explicit "feature
 * not implemented" error rather than a counterfeit pass. Mirrors the
 * {@code WatchlistCheckHandler} ratchet (P0-#3, api #81).
 *
 * <p>P1 fix: see hygiene wave 2026-05-07.
 *
 * <p>TODO: Integrate with OCR/address validation service for automated extraction.
 *          Add address matching against government databases. Wire actual media
 *          storage (S3/equivalent) so {@code document_stored=true} reflects
 *          reality. Remove this profile gate once a real implementation ships.
 */
@Component
@Profile("dev")
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
