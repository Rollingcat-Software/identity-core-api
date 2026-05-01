package com.fivucsas.identity.application.service.mfa;

import java.util.Map;

/**
 * Result of {@link VerifyMfaStepService#execute(VerifyMfaStepRequest)}.
 *
 * <p>Carries an HTTP-status hint and a body map that the controller renders
 * directly into the response. We avoid {@code ResponseEntity} here so the
 * service stays HTTP-agnostic and easy to unit-test without MockMvc.
 *
 * <p>The body shape is preserved verbatim from the original
 * {@code AuthController.verifyMfaStep} so the wire contract of
 * {@code POST /auth/mfa/step} does not regress.
 */
public record VerifyMfaStepResponse(Status status, Map<String, Object> body) {

    public enum Status { OK, BAD_REQUEST, UNAUTHORIZED }

    public static VerifyMfaStepResponse passthrough(Map<String, Object> body) {
        return new VerifyMfaStepResponse(Status.OK, body);
    }

    public static VerifyMfaStepResponse failed(String message) {
        return new VerifyMfaStepResponse(Status.OK,
                Map.of("status", "FAILED", "message", message));
    }

    public static VerifyMfaStepResponse error(String message) {
        return new VerifyMfaStepResponse(Status.OK,
                Map.of("status", "ERROR", "message", message));
    }

    public static VerifyMfaStepResponse badRequest(String message) {
        return new VerifyMfaStepResponse(Status.BAD_REQUEST,
                Map.of("status", "ERROR", "message", message));
    }

    public static VerifyMfaStepResponse unauthorized(String message) {
        return new VerifyMfaStepResponse(Status.UNAUTHORIZED,
                Map.of("status", "ERROR", "message", message));
    }

    public static VerifyMfaStepResponse methodAlreadyUsed() {
        return new VerifyMfaStepResponse(Status.BAD_REQUEST, Map.of(
                "status", "ERROR",
                "error", "METHOD_ALREADY_USED",
                "message", "You cannot use the same authentication method for multiple steps."
        ));
    }
}
