package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class ManageEnrollmentService implements ManageEnrollmentUseCase {

    private static final Set<AuthMethodType> BIOMETRIC_TYPES = Set.of(
            AuthMethodType.FACE, AuthMethodType.FINGERPRINT, AuthMethodType.VOICE);

    private final UserEnrollmentRepositoryPort userEnrollmentRepository;
    private final UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;
    private final BiometricServicePort biometricServicePort;
    private final NfcCardRepositoryPort nfcCardRepository;
    private final WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    private final UserDeviceRepositoryPort userDeviceRepository;
    private final TenantFilterBypass tenantFilterBypass;

    @Override
    @Transactional
    public List<EnrollmentResponse> getUserEnrollments(UUID userId) {
        // A user's enrollments are USER-centric — they live in the user's own
        // tenant, not whichever tenant a ROOT is currently browsing (X-Tenant-ID).
        // Without this bypass, the @Filter(tenantFilter) on UserEnrollment/User
        // scopes the reads to the ACTIVE tenant: when a ROOT views their own (or a
        // foreign user's) auth methods while switched to another tenant, the real
        // rows are filtered out, so (a) the list shows 0 methods and (b) the lazy
        // EMAIL_OTP/QR_CODE provisioning thinks the rows are missing and re-inserts
        // them → uq_user_enrollment violation at flush → 500. Resolving by user id
        // is single-tenant by construction (a user belongs to one tenant), so the
        // bypass is not a cross-tenant leak; authorization already happened at the
        // controller @PreAuthorize before we get here.
        return tenantFilterBypass.runWithoutTenantFilter(() -> {
            ensureSessionBoundEnrollments(userId);
            return userEnrollmentRepository.findAllByUserId(userId).stream()
                    .map(EnrollmentResponse::from)
                    .toList();
        });
    }

    /**
     * EMAIL_OTP and QR_CODE are not really "enrollable" methods — they have
     * no per-user secret to bind. EMAIL_OTP is bound to the account email at
     * registration; QR_CODE is session-scoped (the auth flow's QR step issues
     * a fresh server-side session at sign-in time, so any account can use it).
     * Lazily upsert a status=ENROLLED row the first time a user's enrollments
     * are listed so the UI doesn't have to special-case them. Idempotent:
     * existing rows (including REVOKED) are left alone.
     */
    private void ensureSessionBoundEnrollments(UUID userId) {
        ensureAutoBoundEnrollment(userId, AuthMethodType.EMAIL_OTP);
        ensureAutoBoundEnrollment(userId, AuthMethodType.QR_CODE);
        // #21 — device-implicit methods. APPROVE_LOGIN and PASSKEY are seeded
        // requires_enrollment=true, but they have no biometric "enrollment" flow:
        // APPROVE_LOGIN works once the user has ANY registered device (the approver
        // POLLS /auth/approve-login/pending — no FCM push token is involved, so we
        // must NOT gate on a push token the poll-based mobile app never sets;
        // devices are created on mobile login, see ManageDeviceService #15);
        // PASSKEY works once the user has a discoverable WebAuthn credential.
        // Without a row they were reported as a blocking "not enrolled" in the
        // auth-methods UI. Bind them ENROLLED — but ONLY when the backing data
        // actually exists, so an unprovisioned account still correctly shows them
        // as not-yet-usable.
        if (hasApproverDevice(userId)) {
            ensureAutoBoundEnrollment(userId, AuthMethodType.APPROVE_LOGIN);
        }
        if (hasDiscoverablePasskey(userId)) {
            ensureAutoBoundEnrollment(userId, AuthMethodType.PASSKEY);
        }
    }

    /**
     * APPROVE_LOGIN is device-implicit: usable once the user has ANY registered
     * device. The approver polls for pending requests, so no FCM push token is
     * required (gating on push token left it permanently un-enrollable).
     */
    private boolean hasApproverDevice(UUID userId) {
        try {
            return !userDeviceRepository.findAllByUserId(userId).isEmpty();
        } catch (Exception e) {
            log.debug("APPROVE_LOGIN device check skipped for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    /** PASSKEY is device-implicit: usable once a discoverable credential exists. */
    private boolean hasDiscoverablePasskey(UUID userId) {
        try {
            return webAuthnCredentialRepository.findAllByUserId(userId).stream()
                    .anyMatch(com.fivucsas.identity.entity.WebAuthnCredential::isDiscoverable);
        } catch (Exception e) {
            log.debug("PASSKEY credential check skipped for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void autoBindEnrollment(UUID userId, AuthMethodType methodType) {
        // Runs in a SEPARATE transaction (see interface javadoc): even if the
        // create/save below fails (e.g. a unique-constraint race), only THIS tx
        // rolls back — the caller's WebAuthn credential save still commits.
        ensureAutoBoundEnrollment(userId, methodType);
    }

    private void ensureAutoBoundEnrollment(UUID userId, AuthMethodType methodType) {
        if (userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .isPresent()) {
            return;
        }
        userRepository.findById(userId).ifPresent(user -> {
            if (methodType == AuthMethodType.EMAIL_OTP
                    && (user.getEmail() == null || user.getEmail().isBlank())) {
                return;
            }
            if (user.getTenant() == null) {
                return;
            }
            UserEnrollment enrollment = UserEnrollment.builder()
                    .user(user)
                    .tenant(user.getTenant())
                    .authMethodType(methodType)
                    .build();
            enrollment.completeEnrollment("{}");
            try {
                userEnrollmentRepository.save(enrollment);
            } catch (Exception e) {
                log.debug("{} auto-enrollment skipped for user {}: {}",
                        methodType, userId, e.getMessage());
            }
        });
    }

    @Override
    @Transactional
    public EnrollmentResponse startEnrollment(UUID userId, UUID tenantId, AuthMethodType methodType) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseGet(() -> {
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
                    Tenant tenant = tenantRepository.findById(tenantId)
                            .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));
                    return UserEnrollment.builder()
                            .user(user)
                            .tenant(tenant)
                            .authMethodType(methodType)
                            .build();
                });

        // Only auto-complete for methods that don't require external async data
        // (PASSWORD, EMAIL_OTP, SMS_OTP, QR_CODE, NFC_DOCUMENT). All others stay
        // PENDING until the actual enrollment flow completes via completeEnrollment().
        if (EnrollmentHealthService.AUTO_COMPLETE_TYPES.contains(methodType)) {
            enrollment.completeEnrollment("{}");
        } else {
            enrollment.startEnrollment();
        }
        // AUDIT_2026-04-28 EDGE-P1 #3: two parallel callers can both reach save()
        // here, the second hitting the (user_id, auth_method_type) unique
        // constraint and surfacing as a 500. Catch the conflict, re-fetch the
        // committed row from the winner and return that — idempotent semantics,
        // matches the "first call wins" intent.
        try {
            return EnrollmentResponse.from(userEnrollmentRepository.save(enrollment));
        } catch (DataIntegrityViolationException conflict) {
            log.info("startEnrollment race detected for user={} method={} — re-fetching winner",
                    userId, methodType);
            UserEnrollment winner = userEnrollmentRepository
                    .findByUserIdAndAuthMethodType(userId, methodType)
                    .orElseThrow(() -> conflict);
            return EnrollmentResponse.from(winner);
        }
    }

    @Override
    @Transactional
    public EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData) {
        return completeEnrollment(userId, methodType, enrollmentData, null, null);
    }

    @Override
    @Transactional
    public EnrollmentResponse completeEnrollment(UUID userId,
                                                 AuthMethodType methodType,
                                                 String enrollmentData,
                                                 BigDecimal qualityScore,
                                                 BigDecimal livenessScore) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseGet(() -> {
                    // Upsert: a first-time / out-of-band completion (no prior PENDING
                    // row from startEnrollment) CREATES the row instead of throwing
                    // EntityNotFoundException — which, inside a caller's transaction,
                    // would mark it rollback-only and 500 the commit (the WebAuthn
                    // fingerprint bug class). Mirrors startEnrollment's create path.
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
                    if (user.getTenant() == null) {
                        throw new EntityNotFoundException("User has no tenant: " + userId);
                    }
                    return UserEnrollment.builder()
                            .user(user)
                            .tenant(user.getTenant())
                            .authMethodType(methodType)
                            .build();
                });

        enrollment.completeEnrollment(enrollmentData, qualityScore, livenessScore);
        return EnrollmentResponse.from(userEnrollmentRepository.save(enrollment));
    }

    /**
     * Best-effort score UPSERT: persists biometric quality + liveness scores for
     * a user's enrollment of the given method. Used by biometric enrollment
     * endpoints (face/voice) to record the biometric-processor scores.
     *
     * <p>P1-3 fix: the web FACE flow records scores during the /enroll step
     * BEFORE the user_enrollments row is created (createEnrollment runs after).
     * Previously this method only updated an existing row and silently no-op'd
     * when none existed yet — so every score was dropped on the floor and prod
     * rows all had NULL quality_score / liveness_score. We now CREATE a PENDING
     * row carrying the scores when none exists; the subsequent createEnrollment
     * ({@link #startEnrollment}) leaves the scores intact (it only flips status
     * for non-auto-complete types like FACE), and the final /complete preserves
     * them too (see {@code UserEnrollment.completeEnrollment(String,BigDecimal,
     * BigDecimal)} which no longer nulls existing scores).
     *
     * <p>Best-effort throughout: never throws so the biometric upload itself is
     * not failed by admin bookkeeping. The created row's tenant == the owning
     * user's tenant, which equals the active {@code TenantContext} for the
     * enrolling user — so the Hibernate {@code tenantFilter} read + insert stay
     * consistent (P0-1). The {@link DataIntegrityViolationException} catch
     * mirrors {@link #startEnrollment}'s race handling.
     */
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordBiometricScores(UUID userId,
                                       AuthMethodType methodType,
                                       BigDecimal qualityScore,
                                       BigDecimal livenessScore) {
        if (qualityScore == null && livenessScore == null) {
            return;
        }

        if (userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, methodType).isEmpty()) {
            // Row not created yet — the web enrolls the biometric BEFORE creating
            // the enrollment row (createEnrollment runs afterwards). Stage the row
            // now so the scores have somewhere to live. We delegate to
            // startEnrollment(), the existing sanctioned row-constructor (it owns
            // user/tenant resolution + the unique-constraint race handling), using
            // the active TenantContext tenant — which equals the enrolling user's
            // tenant (set by TenantBindFromAuthFilter) and the row's tenant, so the
            // Hibernate tenantFilter read + insert stay consistent (P0-1). For FACE/
            // VOICE (not AUTO_COMPLETE_TYPES) startEnrollment lands a PENDING row
            // without scores; we record them in the second step below.
            UUID tenantId = TenantContext.getCurrentTenant();
            if (tenantId == null) {
                return; // best-effort: no active tenant to anchor the row to
            }
            try {
                startEnrollment(userId, tenantId, methodType);
            } catch (RuntimeException e) {
                // User/tenant unresolved, or a concurrent writer won the race.
                // Either way, fall through to the score write which no-ops if the
                // row still isn't visible — never fail the biometric upload.
                log.debug("recordBiometricScores could not pre-create row for user={} method={}: {}",
                        userId, methodType, e.getMessage());
            }
        }

        userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, methodType)
                .ifPresent(enrollment -> {
                    enrollment.recordScores(qualityScore, livenessScore);
                    userEnrollmentRepository.save(enrollment);
                });
    }

    @Override
    @Transactional
    public void revokeEnrollment(UUID userId, AuthMethodType methodType) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseThrow(() -> new EntityNotFoundException("Enrollment not found for user: " + userId + " method: " + methodType));

        // Clean up backing data for methods that have external storage
        if (BIOMETRIC_TYPES.contains(methodType)) {
            deleteBiometricData(userId, methodType);
        }
        cleanupMethodData(userId, methodType);

        enrollment.revoke();
        userEnrollmentRepository.save(enrollment);
    }

    private void cleanupMethodData(UUID userId, AuthMethodType methodType) {
        try {
            switch (methodType) {
                case NFC_DOCUMENT -> {
                    List<NfcCard> cards = nfcCardRepository.findByUserIdAndIsActiveTrue(userId);
                    for (NfcCard card : cards) {
                        card.deactivate();
                        nfcCardRepository.save(card);
                    }
                    if (!cards.isEmpty()) {
                        log.info("Deactivated {} NFC cards for user: {}", cards.size(), userId);
                    }
                }
                case HARDWARE_KEY -> {
                    // Hardware keys have transports like "usb", "nfc", "ble" (not "internal")
                    var credentials = webAuthnCredentialRepository.findAllByUserId(userId).stream()
                            .filter(c -> c.getTransports() == null || !c.getTransports().contains("internal"))
                            .toList();
                    for (var cred : credentials) {
                        webAuthnCredentialRepository.deleteById(cred.getId());
                    }
                    if (!credentials.isEmpty()) {
                        log.info("Deleted {} hardware key credentials for user: {}", credentials.size(), userId);
                    }
                }
                case FINGERPRINT -> {
                    // Platform authenticators have "internal" transport
                    var credentials = webAuthnCredentialRepository.findAllByUserId(userId).stream()
                            .filter(c -> c.getTransports() != null && c.getTransports().contains("internal"))
                            .toList();
                    for (var cred : credentials) {
                        webAuthnCredentialRepository.deleteById(cred.getId());
                    }
                    if (!credentials.isEmpty()) {
                        log.info("Deleted {} fingerprint credentials for user: {}", credentials.size(), userId);
                    }
                }
                default -> { /* no additional cleanup needed */ }
            }
        } catch (Exception e) {
            log.warn("Failed to clean up {} data for user: {}. Revocation will proceed. Error: {}",
                    methodType, userId, e.getMessage());
        }
    }

    private void deleteBiometricData(UUID userId, AuthMethodType methodType) {
        try {
            switch (methodType) {
                case FACE -> {
                    biometricServicePort.deleteFace(userId);
                    log.info("Biometric data deleted from external service for user: {} method: {}", userId, methodType);
                }
                case VOICE -> {
                    biometricServicePort.deleteVoice(userId);
                    log.info("Biometric data deleted from external service for user: {} method: {}", userId, methodType);
                }
                case FINGERPRINT -> {
                    // P1.4: server-side fingerprint biometric was a SHA-256 placeholder
                    // and has been removed. Platform fingerprint is WebAuthn-only —
                    // credential cleanup happens in cleanupMethodData() above
                    // (internal-transport WebAuthnCredentials).
                    log.debug("FINGERPRINT enrollment delete: WebAuthn-only, no external biometric to remove for user: {}", userId);
                }
                default -> { /* no-op for non-biometric types */ }
            }
        } catch (Exception e) {
            log.warn("Failed to delete biometric data from external service for user: {} method: {}. " +
                     "Enrollment revocation will proceed. Error: {}", userId, methodType, e.getMessage());
        }
    }
}
