package com.fivucsas.identity.application.port.output;

import java.util.Optional;
import java.util.UUID;

/**
 * Resolves whether — and how — a biometric verify for a person in the REQUESTING
 * tenant may be routed to that person's CANONICAL enrollment under another
 * membership of the SAME identity, gated by consent (Model A, Phase 3).
 *
 * <p>This is the orchestration heart of Model A. The bio store stays keyed by
 * {@code user_id}; "one template per person" is achieved by designating a
 * canonical enrollment and routing CONSENTED cross-tenant verifies to it — never
 * by re-keying the pgvector store.</p>
 */
public interface BiometricConsentResolver {

    /**
     * Where a consented cross-tenant verify should be routed.
     *
     * @param canonicalUserId   the {@code user_id} the bio store is keyed by
     * @param canonicalTenantId the tenant the canonical enrollment lives in
     *                          (forwarded so tenant-scoped bio predicates keep
     *                          matching the canonical tenant)
     */
    record CanonicalTarget(UUID canonicalUserId, UUID canonicalTenantId) {}

    /**
     * Resolves a canonical verify target for a probe that has NO local enrollment
     * in the requesting tenant.
     *
     * <p>Returns a target ONLY when ALL hold:
     * <ol>
     *   <li>the requesting user belongs to an identity,</li>
     *   <li>that identity has an ENROLLED canonical enrollment for {@code method}
     *       in a DIFFERENT tenant, AND</li>
     *   <li>{@code consent(identity, requestingTenant, method) = granted}.</li>
     * </ol>
     * Otherwise {@link Optional#empty()} — the verify path MUST then behave
     * exactly as "not enrolled", leaking NO signal that a template exists
     * elsewhere.</p>
     *
     * <p>The requesting tenant is derived from {@code requestingUserId} (the
     * user's own membership tenant), so callers on the verify path do NOT need to
     * touch the {@code entity.User} aggregate just to read its tenant.</p>
     *
     * @param requestingUserId the user being verified in the requesting tenant
     * @param method           the {@code AuthMethodType} name (e.g. {@code FACE})
     * @return the canonical target, or empty when no consented canonical
     *         enrollment is available
     */
    Optional<CanonicalTarget> resolveConsentedCanonicalTarget(UUID requestingUserId,
                                                              String method);
}
