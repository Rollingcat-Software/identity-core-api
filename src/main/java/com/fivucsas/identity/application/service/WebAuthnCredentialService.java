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
 * Application service for WebAuthn credential lifecycle.
 *
 * <p>Holds the transaction boundary for credential reads/writes so HTTP and
 * auth-handler callers stay free of persistence concerns (P1-Q9, quality
 * review 2026-05-01; T-SEC-TAIL §T4.4 boundary closure 2026-05-04).</p>
 *
 * <p>Controllers and auth handlers must route writes through this service;
 * the {@code WebAuthnRepoWriteBoundaryTest} ArchUnit rule enforces that.
 * Peer application services (e.g. {@code ManageEnrollmentService}) are
 * exempt because they implement the inverse enrollment-revoke lifecycle.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnCredentialService {

    private final WebAuthnCredentialRepositoryPort credentialRepository;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

    /**
     * Persist a brand-new WebAuthn credential and auto-complete the matching
     * enrollment row so {@code biometric_enrollments} stays in sync with
     * actual credentials. Mirrors the inverse delete path
     * ({@link #revokeWebAuthnEnrollmentIfNeeded}).
     *
     * <p>The enrollment side-effect is best-effort: a failure is logged at
     * WARN but never rolls back the credential save, since the credential
     * itself is the source of truth and a missing enrollment row will be
     * reconciled on next login.</p>
     */
    @Transactional
    public WebAuthnCredential saveCredential(WebAuthnCredential credential) {
        WebAuthnCredential saved = credentialRepository.save(credential);
        autoCompleteWebAuthnEnrollment(saved.getUser().getId(), saved.getTransports());
        return saved;
    }

    /**
     * Persist a WebAuthn credential sign-counter advance per WebAuthn §6.1
     * step 17. Caller must have already verified
     * {@link com.fivucsas.identity.infrastructure.webauthn.WebAuthnService#validateSignCount}
     * (this method does not re-validate). No-ops when {@code newSignCount}
     * is not strictly greater than the stored counter — matches the spec
     * note on both-zero authenticators.
     */
    @Transactional
    public void updateSignCount(WebAuthnCredential credential, long newSignCount) {
        if (newSignCount > credential.getSignCount()) {
            credential.updateSignCount(newSignCount);
            credentialRepository.save(credential);
        }
    }

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
     *
     * <p>Mirrors {@link #deleteById(UUID)} semantics: when the last credential
     * of a given transport class disappears, the corresponding enrollment
     * (FINGERPRINT for platform, HARDWARE_KEY for roaming) is auto-revoked.
     * Without this, calls through {@code DELETE /api/v1/webauthn/credentials/{credentialId}}
     * would leave a stale ENROLLED row and skew MFA availability checks
     * (Copilot review on PR #66).</p>
     */
    @Transactional
    public void deleteByCredentialId(String credentialId) {
        WebAuthnCredential credential = credentialRepository.findByCredentialId(credentialId)
                .orElseThrow(() -> new ResourceNotFoundException("Credential", credentialId));
        UUID userId = credential.getUser().getId();
        String transports = credential.getTransports();

        credentialRepository.deleteByCredentialId(credentialId);

        revokeWebAuthnEnrollmentIfNeeded(userId, transports);
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

    private void autoCompleteWebAuthnEnrollment(UUID userId, String transports) {
        AuthMethodType methodType = resolveWebAuthnMethodType(transports);
        try {
            manageEnrollmentUseCase.completeEnrollment(userId, methodType, "{}");
            log.info("Auto-completed {} enrollment for user {}", methodType, userId);
        } catch (Exception e) {
            log.warn("Failed to auto-complete {} enrollment for user {} after WebAuthn registration: {}",
                    methodType, userId, e.getMessage());
        }
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
