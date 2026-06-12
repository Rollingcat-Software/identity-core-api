package com.fivucsas.identity.application.dto.response;

import java.util.List;

/**
 * Public, unauthenticated description of a tenant's default APP_LOGIN flow,
 * served by {@code GET /api/v1/auth/login-config?tenantId=<uuid>} (task #16 C).
 *
 * <p>This is the FROZEN contract the login UI (agent-web3) renders against. It
 * exposes ONLY what a login surface needs to decide which Layer-1 affordance to
 * show (password field vs. "Sign in with a passkey" vs. "Approve on another
 * device" vs. an OTP/biometric identifier-first step) and how many steps total
 * to expect. It deliberately leaks NO internal IDs (auth_method / step / flow
 * UUIDs), enrollment counts, or other tenant internals.
 *
 * @param tenantId   the tenant the config is for (echoed UUID string)
 * @param tenantName the tenant display name (may be null for the system tenant)
 * @param layer1     the first authentication layer (step-order 1)
 * @param totalSteps the total number of steps in the default flow (>=1); 1 when
 *                   the tenant has no default flow (implicit single-step login)
 * @param laterSteps every step after Layer-1, ordered; empty for a 1-step flow
 * @param engineActive true when the config-driven login engine is enabled for
 *                   this tenant (global flag or per-tenant canary). The login UI
 *                   uses this to switch on the identifier-first experience
 *                   (collect identity on screen 1, authenticate after); when
 *                   false it keeps the legacy single-screen email+password form,
 *                   so the redesign reverts with the engine flag and no redeploy.
 */
public record LoginConfigResponse(
        String tenantId,
        String tenantName,
        Layer1 layer1,
        int totalSteps,
        List<LaterStep> laterSteps,
        boolean engineActive
) {
    /**
     * @param methods            the methods offered at step 1 (one for SEQUENTIAL,
     *                           several for a CHOICE step)
     * @param identifierRequired true when the surface must collect an identifier
     *                           (email/username) up front — i.e. NOT every Layer-1
     *                           method is usernameless. False only when EVERY
     *                           Layer-1 method is usernameless (the user can be
     *                           resolved from the factor alone).
     * @param stepConfig         raw JSON blob from {@code auth_flow_steps.config};
     *                           null when the step carries no extra configuration.
     *                           The runtime/frontend parses this to read
     *                           {@code puzzleConfig} (PUZZLE steps) or
     *                           {@code requireActivePuzzleLiveness} (FACE steps).
     */
    public record Layer1(List<Method> methods, boolean identifierRequired, String stepConfig) {
        /** Backward-compatible 2-arg constructor: stepConfig defaults to null. */
        public Layer1(List<Method> methods, boolean identifierRequired) {
            this(methods, identifierRequired, null);
        }
    }

    /**
     * @param order      the step order (>=2)
     * @param methods    the methods offered at that step
     * @param stepConfig raw JSON blob from {@code auth_flow_steps.config};
     *                   null when the step carries no extra configuration.
     */
    public record LaterStep(int order, List<Method> methods, String stepConfig) {
        /** Backward-compatible 2-arg constructor: stepConfig defaults to null. */
        public LaterStep(int order, List<Method> methods) {
            this(order, methods, null);
        }
    }

    /**
     * @param type               the {@code AuthMethodType} name (e.g. PASSWORD,
     *                           EMAIL_OTP, PASSKEY, APPROVE_LOGIN)
     * @param usernameless       true when this method can begin a login with no
     *                           up-front identifier
     * @param requiresEnrollment true when the user must have enrolled this method
     *                           before it can be used
     */
    public record Method(String type, boolean usernameless, boolean requiresEnrollment) {}
}
