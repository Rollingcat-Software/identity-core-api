package com.fivucsas.identity.application.dto.response;

import java.util.List;
import java.util.UUID;

/**
 * The "person view" returned by {@code GET /api/v1/identity/me} (Phase-2
 * account linking). Exposes the caller's platform-level identity together with
 * every email they control and every tenant membership they hold.
 *
 * <p>This is a CROSS-TENANT read BY DESIGN — the memberships span tenants
 * because they are the one authenticated person's own rows. The service derives
 * the identity from the authenticated caller, never from a request parameter,
 * so no other person's data is reachable here.</p>
 */
public record IdentityMeResponse(
        UUID identityId,
        List<EmailView> emails,
        List<MembershipView> memberships) {

    public record EmailView(String email, boolean verified) {
    }

    public record MembershipView(
            UUID userId,
            UUID tenantId,
            String tenantName,
            String role,
            boolean isActive) {
    }
}
