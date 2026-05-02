package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.WebAuthnCredential;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Application service for WebAuthn credential lifecycle (delete).
 *
 * <p>Holds the transaction boundary for credential deletes so the controller
 * stays HTTP-only (P1-Q9, quality review 2026-05-01).</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnCredentialService {

    private final WebAuthnCredentialRepositoryPort credentialRepository;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

    /**
     * Delete a credential by primary key. Auto-revokes the matching
     * {@link AuthMethodType} (FINGERPRINT for platform, HARDWARE_KEY for
     * roaming) when the last credential of that transport class is removed.
     */
    @Transactional
    public void deleteById(UUID id) {
        WebAuthnCredential credential = credentialRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Credential", id.toString()));
        UUID userId = credential.getUser().getId();
        String transports = credential.getTransports();

        credentialRepository.deleteById(id);

        revokeWebAuthnEnrollmentIfNeeded(userId, transports);
    }

    /**
     * Delete a credential by its WebAuthn credentialId. Throws
     * {@link ResourceNotFoundException} if the credentialId is unknown.
     */
    @Transactional
    public void deleteByCredentialId(String credentialId) {
        if (!credentialRepository.existsByCredentialId(credentialId)) {
            throw new ResourceNotFoundException("Credential", credentialId);
        }
        credentialRepository.deleteByCredentialId(credentialId);
    }

    /**
     * Determines the auth method type for a WebAuthn credential based on its
     * transports field. {@code internal} indicates a platform authenticator
     * (fingerprint/Face ID); all other transports (usb, ble, nfc, hybrid)
     * indicate a roaming/cross-platform hardware key.
     */
    static AuthMethodType resolveWebAuthnMethodType(String transports) {
        if (transports != null && transports.toLowerCase().contains("internal")) {
            return AuthMethodType.FINGERPRINT;
        }
        return AuthMethodType.HARDWARE_KEY;
    }

    /**
     * Revokes the WebAuthn enrollment record if no credentials of the given
     * transport type remain. Keeps the enrollment status in sync with actual
     * credentials: removing the last passkey of a given class auto-marks the
     * method NOT_ENROLLED rather than leaving a stale ENROLLED row.
     */
    private void revokeWebAuthnEnrollmentIfNeeded(UUID userId, String transports) {
        AuthMethodType methodType = resolveWebAuthnMethodType(transports);
        List<WebAuthnCredential> remaining = credentialRepository.findAllByUserId(userId);
        boolean anyOfSameType = remaining.stream().anyMatch(c -> {
            boolean isInternal = c.getTransports() != null && c.getTransports().toLowerCase().contains("internal");
            return methodType == AuthMethodType.FINGERPRINT ? isInternal : !isInternal;
        });

        if (!anyOfSameType) {
            try {
                manageEnrollmentUseCase.revokeEnrollment(userId, methodType);
                log.info("Auto-revoked {} enrollment for user {} after last credential deleted", methodType, userId);
            } catch (Exception e) {
                log.warn("Failed to revoke {} enrollment for user {} after credential deletion: {}",
                        methodType, userId, e.getMessage());
            }
        }
    }
}
