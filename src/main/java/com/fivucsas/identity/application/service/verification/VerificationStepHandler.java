package com.fivucsas.identity.application.service.verification;

import com.fivucsas.identity.entity.VerificationSession;

import java.util.Map;

/**
 * Interface for verification step handlers in the identity verification pipeline.
 * Each handler implements one step type (e.g., DOCUMENT_SCAN, FACE_MATCH).
 */
public interface VerificationStepHandler {

    /**
     * Returns the step type this handler supports (e.g., "DOCUMENT_SCAN", "FACE_MATCH").
     */
    String getStepType();

    /**
     * Executes the verification step against the given session.
     *
     * @param session    the active verification session
     * @param stepNumber the step number within the flow
     * @param data       input data submitted by the client
     * @return result containing success/failure, confidence, and result data
     */
    VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data);

    /**
     * Checks whether this handler supports the given step type string.
     */
    default boolean supports(String stepType) {
        return getStepType().equals(stepType);
    }
}
