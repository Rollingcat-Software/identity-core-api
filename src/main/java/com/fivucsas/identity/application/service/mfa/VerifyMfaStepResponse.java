package com.fivucsas.identity.application.service.mfa;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    public enum Status { OK, BAD_REQUEST, UNAUTHORIZED, CONFLICT }

    public static VerifyMfaStepResponse passthrough(Map<String, Object> body) {
        return new VerifyMfaStepResponse(Status.OK, body);
    }

    public static VerifyMfaStepResponse failed(String message) {
        return new VerifyMfaStepResponse(Status.OK,
                Map.of("status", "FAILED", "message", message));
    }

    /**
     * Failed-step response enriched with recovery context — clients can render
     * the next action without a follow-up GET on session state. Post-audit
     * 2026-04-24 login edge case #5.
     */
    public static VerifyMfaStepResponse failed(
            String message,
            int currentStep,
            int totalSteps,
            String expectedMethod,
            List<String> completedMethods) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "FAILED");
        body.put("message", message);
        body.put("currentStep", currentStep);
        body.put("totalSteps", totalSteps);
        body.put("expectedMethod", expectedMethod);
        body.put("completedMethods", completedMethods != null ? completedMethods : List.of());
        body.put("nextAction", "RETRY_OR_SWITCH_METHOD");
        return new VerifyMfaStepResponse(Status.OK, body);
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

    /**
     * Substitution rejection: the submitted method was completed earlier in
     * the flow and is NOT the expected method at the current step.
     *
     * <p>Mapped to HTTP 409 (Conflict) — the request is well-formed (so 400 is
     * wrong) but conflicts with current session state. Matches the convention
     * established by {@code POST /api/v1/auth/mfa/switch-method}, which has
     * always returned 409 for the same scenario. Post-audit 2026-04-24 login
     * edge case #4.
     *
     * <p>Body carries recovery context (post-audit edge case #5) so clients
     * don't need a follow-up call to render the next action.
     */
    public static VerifyMfaStepResponse methodAlreadyUsed(
            int currentStep,
            int totalSteps,
            Set<String> expectedMethods,
            List<String> completedMethods) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "ERROR");
        body.put("error", "METHOD_ALREADY_USED");
        body.put("message", "You cannot use the same authentication method for multiple steps.");
        body.put("currentStep", currentStep);
        body.put("totalSteps", totalSteps);
        body.put("expectedMethods", expectedMethods != null ? expectedMethods : Set.of());
        body.put("completedMethods", completedMethods != null ? completedMethods : List.of());
        body.put("nextAction", "SWITCH_METHOD");
        return new VerifyMfaStepResponse(Status.CONFLICT, body);
    }

    /**
     * Step-binding rejection (P1-1): the submitted method is not part of the
     * CURRENT step's permitted set (the step's available methods plus its
     * configured fallback). Without this guard a caller could submit ANY
     * registered method for the current step (e.g. answer a FACE step with a
     * TOTP code), defeating per-step method enforcement.
     *
     * <p>Mapped to HTTP 409 (Conflict) — the request is well-formed but
     * conflicts with the session's current-step configuration. Mirrors the
     * {@code METHOD_NOT_PERMITTED} contract already enforced by
     * {@code POST /api/v1/auth/mfa/switch-method}. The guard runs BEFORE handler
     * dispatch, so a non-permitted method has no verification side-effect.
     */
    public static VerifyMfaStepResponse methodNotPermitted(
            int currentStep,
            int totalSteps,
            Set<String> permittedMethods,
            List<String> completedMethods) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "ERROR");
        body.put("error", "METHOD_NOT_PERMITTED");
        body.put("message", "This authentication method is not permitted for the current step.");
        body.put("currentStep", currentStep);
        body.put("totalSteps", totalSteps);
        body.put("permittedMethods", permittedMethods != null ? permittedMethods : Set.of());
        body.put("completedMethods", completedMethods != null ? completedMethods : List.of());
        body.put("nextAction", "SWITCH_METHOD");
        return new VerifyMfaStepResponse(Status.CONFLICT, body);
    }
}
