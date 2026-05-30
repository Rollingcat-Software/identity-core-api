package com.fivucsas.identity.application.dto.response;

import java.util.List;

/**
 * Advisory analysis of what happens if a given flow becomes the default for its
 * operation type. Surfaced to admins BEFORE they confirm "Make Default" so they
 * don't accidentally lock users out by defaulting to a flow that requires an
 * auth method those users have not enrolled.
 *
 * @param flowId         the flow being evaluated
 * @param flowName       its display name
 * @param operationType  the operation it would become default for (e.g. APP_LOGIN)
 * @param activeUsers    number of (non-deleted) users in the tenant
 * @param usersAtRisk    how many of those users cannot complete this flow with
 *                       their currently-enrolled methods (would be locked out).
 *                       Usernameless Layer-1 methods (PASSKEY/APPROVE_LOGIN/
 *                       QR_CODE) are NOT counted as a lockout risk — the factor
 *                       proves its own enrollment, so requiring it as step 1
 *                       cannot strand a user the way an un-enrolled OTP step can.
 * @param methods        per-method enrollment coverage for the flow's required
 *                       (non-PASSWORD) methods
 * @param noRecoveryWarning true when the flow offers no usable recovery factor —
 *                       i.e. it has NO PASSWORD step and EVERY required step is a
 *                       single usernameless factor with no alternative. Losing
 *                       the device then locks the user out with no fallback, so
 *                       the admin should be warned before defaulting to it.
 */
public record AuthFlowDefaultImpactResponse(
        String flowId,
        String flowName,
        String operationType,
        long activeUsers,
        long usersAtRisk,
        List<MethodCoverage> methods,
        boolean noRecoveryWarning
) {
    /**
     * @param method        the auth method type (e.g. SMS_OTP)
     * @param choice        true if it is one option within a CHOICE step (the
     *                      user only needs one of the group), false if it is a
     *                      strictly-required sequential step
     * @param enrolledUsers active users who have this method ENROLLED
     * @param missingUsers  active users who do NOT have it (activeUsers - enrolledUsers)
     */
    public record MethodCoverage(
            String method,
            boolean choice,
            long enrolledUsers,
            long missingUsers
    ) {}
}
