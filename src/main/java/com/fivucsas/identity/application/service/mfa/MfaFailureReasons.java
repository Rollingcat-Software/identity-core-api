package com.fivucsas.identity.application.service.mfa;

/**
 * Audit reasons a step handler reports through {@link MfaStepResult#fail(String)}.
 * These values land in the security audit log, so they must name the real cause.
 */
public final class MfaFailureReasons {

    /** The verifier compared the probe against the enrolled template and found no match. */
    public static final String FACE_MISMATCH = "face_mismatch";
    /** The biometric processor flagged the capture as a presentation attack. */
    public static final String FACE_SPOOF_DETECTED = "face_spoof_detected";
    /** The biometric processor answered without a {@code verified} verdict (fail-closed). */
    public static final String FACE_VERIFIER_NO_VERDICT = "face_verifier_no_verdict";
    /** Neither a face image nor a usable embedding was submitted. */
    public static final String MISSING_FACE_IMAGE = "missing_face_image";
    /** Face verification failed and the handler did not report a specific cause. */
    public static final String FACE_VERIFICATION_FAILED = "face_verification_failed";

    private MfaFailureReasons() {
    }
}
