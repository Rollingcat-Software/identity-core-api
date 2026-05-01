package com.fivucsas.identity.application.service.mfa;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;

import java.util.Map;

/**
 * Strategy for verifying a single step of an N-step MFA flow.
 *
 * <p>One implementation exists per {@link AuthMethodType}; Spring auto-injects
 * the {@code List<VerifyMfaStepHandler>} into {@link VerifyMfaStepService},
 * which indexes them into an {@link java.util.EnumMap} keyed by
 * {@link #supports()}. Each handler is a thin wrapper around the per-method
 * correctness check that previously lived inline in
 * {@code AuthController.verifyMfaStep}.
 *
 * <p>Handlers MUST NOT:
 * <ul>
 *   <li>Mutate the {@link MfaSession} (step counter, completed methods).</li>
 *   <li>Emit audit log entries.</li>
 *   <li>Mint JWTs or refresh tokens.</li>
 * </ul>
 * Those concerns are owned by the orchestrator. Handlers do exactly one
 * thing: verify whether the supplied {@code data} satisfies their method.
 */
public interface VerifyMfaStepHandler {

    AuthMethodType supports();

    MfaStepResult verify(MfaSession session, User user, Map<String, Object> data);
}
