package com.fivucsas.identity.application.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * Response for a successful public self-service tenant onboarding request.
 *
 * <p>Intentionally minimal — no tokens are issued. The admin must verify their
 * email before the tenant becomes ACTIVE and before they can log in. The
 * frontend uses {@code status} to render the "check your inbox" screen.</p>
 */
@Getter
@Builder
public class TenantOnboardingResponse {

    /** UUID of the freshly-created tenant. */
    private final String tenantId;

    /** Final (possibly de-duplicated) slug assigned to the tenant. */
    private final String slug;

    /** Organisation display name. */
    private final String orgName;

    /** UUID of the first TENANT_ADMIN user. */
    private final String adminUserId;

    /** Admin email the verification link was sent to. */
    private final String adminEmail;

    /** Primary email domain claimed for the tenant. */
    private final String emailDomain;

    /**
     * Tenant status immediately after registration — {@code PENDING} when admin
     * approval is required, otherwise {@code TRIAL}. Becomes {@code ACTIVE} once
     * the admin verifies their email (and, if required, an admin approves).
     */
    private final String status;

    /**
     * True when {@code app.onboarding.require-admin-approval} is enabled — the
     * tenant stays PENDING for a SUPER_ADMIN to approve even after the admin
     * verifies their email. Lets the frontend tailor the messaging.
     */
    private final boolean requiresAdminApproval;

    /** Human-readable next-step hint for the UI. */
    private final String message;
}
