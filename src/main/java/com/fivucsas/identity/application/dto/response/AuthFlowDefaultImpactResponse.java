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
 *                       their currently-enrolled methods (would be locked out)
 * @param methods        per-method enrollment coverage for the flow's required
 *                       (non-PASSWORD) methods
 */
public record AuthFlowDefaultImpactResponse(
        String flowId,
        String flowName,
        String operationType,
        long activeUsers,
        long usersAtRisk,
        List<MethodCoverage> methods
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
