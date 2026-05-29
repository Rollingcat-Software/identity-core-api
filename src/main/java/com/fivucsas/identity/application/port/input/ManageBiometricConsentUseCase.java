package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.BiometricConsentRequest;
import com.fivucsas.identity.application.dto.response.BiometricConsentResponse;

import java.util.List;
import java.util.UUID;

/**
 * Input port for managing a person's per-tenant biometric consent (Model A,
 * Phase 3). The caller acts on their OWN identity only.
 */
public interface ManageBiometricConsentUseCase {

    /**
     * Lists all consent rows for the given identity.
     *
     * @param identityId the caller's identity
     * @return the caller's consents (may be empty)
     */
    List<BiometricConsentResponse> listConsents(UUID identityId);

    /**
     * Grants or revokes consent for one (tenant, method). Upserts the matching
     * row. The caller may only manage consent for a tenant where their identity
     * has a membership.
     *
     * @param identityId  the caller's identity
     * @param actorUserId the acting user id (for audit attribution); may be null
     * @param request     the grant/revoke command
     * @return the resulting consent row
     */
    BiometricConsentResponse setConsent(UUID identityId, UUID actorUserId,
                                        BiometricConsentRequest request);
}
