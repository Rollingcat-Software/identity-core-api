package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.entity.WebAuthnCredential;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Service that validates enrollment statuses against actual backing data.
 *
 * The user_enrollments table may report ENROLLED for a method whose real data
 * has been deleted or invalidated. This service cross-checks each enrollment
 * and auto-revokes stale ones so that MFA method selection only shows
 * genuinely usable options.
 */
@Service
@Slf4j
public class EnrollmentHealthService {

    private static final String TOTP_SECRET_PREFIX = "totp:secret:";

    /** Methods that are always considered valid when enrolled (no external data to verify). */
    private static final Set<AuthMethodType> ALWAYS_VALID_TYPES = Set.of(
            AuthMethodType.PASSWORD,
            AuthMethodType.QR_CODE
    );

    /**
     * Methods that can be auto-completed on startEnrollment (no async external flow).
     *
     * SMS_OTP and QR_CODE were intentionally REMOVED here on 2026-04-28 — they were
     * being silently flipped to ENROLLED without any real verification of the user's
     * phone number / QR session. They now require an actual verify step (OTP code
     * for SMS, approved session for QR) before the row is marked complete.
     *
     * EMAIL_OTP is also removed: every user has a NOT NULL email column, so the row
     * is now auto-created as ENROLLED in ManageEnrollmentService.getUserEnrollments
     * rather than via this auto-complete path.
     *
     * NFC_DOCUMENT remains here because the NfcController.enrollCard endpoint already
     * verifies the card (NDEFReader scan + cardSerial persistence) before calling
     * startEnrollment — by that point the backing data is real.
     *
     * PASSWORD remains here because it's set during user creation, not via this flow.
     */
    public static final Set<AuthMethodType> AUTO_COMPLETE_TYPES = Set.of(
            AuthMethodType.PASSWORD,
            AuthMethodType.NFC_DOCUMENT
    );

    private final UserEnrollmentRepositoryPort userEnrollmentRepository;
    private final UserRepository userRepository;
    private final WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    private final UserDeviceRepositoryPort userDeviceRepository;
    private final NfcCardRepositoryPort nfcCardRepository;
    private final StringRedisTemplate redisTemplate;
    private final BiometricServicePort biometricServicePort;

    /**
     * Spring Data {@code User} repository — used ONLY for the cross-membership
     * identity helpers ({@code findIdentityIdById} / {@code findTenantIdById}),
     * which the domain {@link UserRepository} port does not expose. Mirrors
     * {@code BiometricConsentService}, the other established cross-membership
     * resolver. NOT used for the per-user lookups (those stay on the domain port).
     */
    private final com.fivucsas.identity.repository.UserRepository userJpaRepository;

    /**
     * Cross-membership NFC enrollment resolution (NFC_DOCUMENT only). When false
     * (default), enrollment health reads ONLY the active membership's cards —
     * byte-identical to legacy behavior. When true, a card enrolled under another
     * of the person's (identity) linked memberships counts as enrolled. NFC
     * possession is identity-level → EXEMPT from biometric consent (product
     * decision); every cross-identity match is audit-logged.
     */
    private final boolean crossMembershipNfcEnabled;

    public EnrollmentHealthService(
            UserEnrollmentRepositoryPort userEnrollmentRepository,
            UserRepository userRepository,
            WebAuthnCredentialRepositoryPort webAuthnCredentialRepository,
            UserDeviceRepositoryPort userDeviceRepository,
            NfcCardRepositoryPort nfcCardRepository,
            StringRedisTemplate redisTemplate,
            BiometricServicePort biometricServicePort,
            com.fivucsas.identity.repository.UserRepository userJpaRepository,
            @Value("${app.identity.cross-membership-enrollment-resolution:false}")
            boolean crossMembershipNfcEnabled) {
        this.userEnrollmentRepository = userEnrollmentRepository;
        this.userRepository = userRepository;
        this.webAuthnCredentialRepository = webAuthnCredentialRepository;
        this.userDeviceRepository = userDeviceRepository;
        this.nfcCardRepository = nfcCardRepository;
        this.redisTemplate = redisTemplate;
        this.biometricServicePort = biometricServicePort;
        this.userJpaRepository = userJpaRepository;
        this.crossMembershipNfcEnabled = crossMembershipNfcEnabled;
    }

    /**
     * Validates all ENROLLED enrollments for a user against actual backing data.
     * Returns a map of method type to whether it is genuinely usable.
     * Stale enrollments (ENROLLED but no backing data) are auto-revoked.
     *
     * @param userId the user whose enrollments to validate
     * @return map of AuthMethodType to validity (true = usable, false = stale/revoked)
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Map<AuthMethodType, Boolean> validateEnrollments(UUID userId) {
        List<UserEnrollment> enrollments = userEnrollmentRepository.findAllByUserId(userId);
        Optional<User> userOpt = userRepository.findById(userId);

        if (userOpt.isEmpty()) {
            log.warn("Enrollment health check requested for non-existent user: {}", userId);
            return Collections.emptyMap();
        }

        User user = userOpt.get();
        Map<AuthMethodType, Boolean> healthMap = new EnumMap<>(AuthMethodType.class);

        for (UserEnrollment enrollment : enrollments) {
            if (enrollment.getStatus() != EnrollmentStatus.ENROLLED) {
                healthMap.put(enrollment.getAuthMethodType(), false);
                continue;
            }

            boolean valid = checkBackingData(enrollment.getAuthMethodType(), userId, user);
            healthMap.put(enrollment.getAuthMethodType(), valid);

            if (!valid) {
                log.info("Auto-revoking stale {} enrollment for user {} (backing data missing)",
                        enrollment.getAuthMethodType(), userId);
                enrollment.revoke();
                userEnrollmentRepository.save(enrollment);
            }
        }

        // Cross-membership NFC (flag-gated, NFC only): a person may hold their NFC
        // card under one membership (e.g. tenant FIVUCSAS) but log in via another
        // (e.g. tenant Marmara, reached through hosted login) whose active row has
        // NO NFC user_enrollments row at all — so the loop above never produced an
        // NFC entry. Surface NFC as enrolled when a sibling membership has an
        // active card, so AvailableMethodsResolver offers it. (When the active row
        // DOES have an NFC enrollment, hasActiveNfcCard already resolved it above —
        // and that same cross-membership hit also prevents an erroneous auto-revoke
        // of a legitimately empty active-row card set.)
        if (crossMembershipNfcEnabled && !Boolean.TRUE.equals(healthMap.get(AuthMethodType.NFC_DOCUMENT))
                && hasCrossMembershipActiveNfcCard(userId)) {
            healthMap.put(AuthMethodType.NFC_DOCUMENT, true);
        }

        return healthMap;
    }

    /**
     * Checks whether the backing data for a given auth method actually exists.
     */
    private boolean checkBackingData(AuthMethodType methodType, UUID userId, User user) {
        if (ALWAYS_VALID_TYPES.contains(methodType)) {
            return true;
        }

        return switch (methodType) {
            case TOTP -> hasTotpSecret(userId, user);
            case FINGERPRINT -> hasWebAuthnCredential(userId, true);
            case HARDWARE_KEY -> hasWebAuthnCredential(userId, false);
            case FACE -> hasBiometricData(userId, AuthMethodType.FACE);
            case VOICE -> hasBiometricData(userId, AuthMethodType.VOICE);
            case NFC_DOCUMENT -> hasActiveNfcCard(userId);
            case SMS_OTP -> user.getPhoneNumber() != null && !user.getPhoneNumber().isBlank();
            case EMAIL_OTP -> user.getEmail() != null && !user.getEmail().isBlank();
            // #21 — device-implicit methods. APPROVE_LOGIN is usable while the
            // user has ANY registered device (the approver POLLS — no FCM push
            // token is involved); PASSKEY while a discoverable WebAuthn credential
            // exists. So a bound enrollment auto-revokes honestly if the backing
            // device/passkey is later removed.
            case APPROVE_LOGIN -> hasApproverDevice(userId);
            case PASSKEY -> hasDiscoverablePasskey(userId);
            default -> true; // Unknown future types default to valid
        };
    }

    /**
     * TOTP is valid if the user has a two_factor_secret in the DB or a secret in Redis.
     */
    private boolean hasTotpSecret(UUID userId, User user) {
        if (user.getTwoFactorSecret() != null && !user.getTwoFactorSecret().isBlank()) {
            return true;
        }
        try {
            String redisKey = TOTP_SECRET_PREFIX + userId;
            return Boolean.TRUE.equals(redisTemplate.hasKey(redisKey));
        } catch (Exception e) {
            log.warn("Redis unavailable during TOTP health check for user {}: {}", userId, e.getMessage());
            // Fail open: if Redis is down but DB has no secret, consider it invalid
            return false;
        }
    }

    /**
     * APPROVE_LOGIN is usable while the user has ANY registered device. The
     * approver polls for pending requests, so no FCM push token is required
     * (gating on a push token the poll-based mobile app never sets left it
     * permanently un-enrollable).
     */
    private boolean hasApproverDevice(UUID userId) {
        return !userDeviceRepository.findAllByUserId(userId).isEmpty();
    }

    /** PASSKEY is usable while the user has a discoverable WebAuthn credential. */
    private boolean hasDiscoverablePasskey(UUID userId) {
        return webAuthnCredentialRepository.findAllByUserId(userId).stream()
                .anyMatch(WebAuthnCredential::isDiscoverable);
    }

    /**
     * Checks for WebAuthn credentials, distinguishing platform (fingerprint) from
     * cross-platform (hardware key) authenticators based on the transports field.
     *
     * @param platformAuthenticator true for FINGERPRINT (internal transport),
     *                              false for HARDWARE_KEY (usb, ble, nfc)
     */
    private boolean hasWebAuthnCredential(UUID userId, boolean platformAuthenticator) {
        List<WebAuthnCredential> credentials = webAuthnCredentialRepository.findAllByUserId(userId);
        if (credentials.isEmpty()) {
            return false;
        }

        for (WebAuthnCredential credential : credentials) {
            String transports = credential.getTransports();
            boolean isInternal = transports != null && transports.toLowerCase().contains("internal");

            if (platformAuthenticator && isInternal) {
                return true;
            }
            if (!platformAuthenticator && !isInternal) {
                return true;
            }
        }

        // Has credentials but none match the expected transport type.
        // Only consider it valid if some credentials have NO transport metadata (null/blank),
        // since we can't distinguish platform vs cross-platform in that case.
        // If all credentials have explicit transport types that don't match, it's invalid.
        return credentials.stream().anyMatch(c ->
                c.getTransports() == null || c.getTransports().isBlank());
    }

    /**
     * Checks whether biometric data (face/voice) exists for the user.
     * Biometric embeddings live in biometric_db (separate database managed by biometric-processor),
     * NOT in the enrollment_data field of user_enrollments (which is always "{}").
     * We trust the enrollment status if the biometric service is healthy.
     * If the service is down, fail open (don't revoke).
     */
    private boolean hasBiometricData(UUID userId, AuthMethodType biometricType) {
        try {
            Map<String, Object> health = biometricServicePort.checkHealth();
            String status = health != null ? String.valueOf(health.getOrDefault("status", "")) : "";
            if (!"ok".equalsIgnoreCase(status) && !"healthy".equalsIgnoreCase(status)) {
                log.warn("Biometric service unhealthy during {} health check for user {}", biometricType, userId);
            }
            // Biometric data is in biometric_db (face_embeddings/voice_enrollments tables).
            // We cannot query it from identity-core-api. Trust the enrollment if service is reachable.
            return true;
        } catch (Exception e) {
            log.warn("Biometric service unreachable during {} health check for user {}: {}",
                    biometricType, userId, e.getMessage());
            // Fail open: don't revoke when service is unreachable
            return true;
        }
    }

    /**
     * Checks whether the user has at least one active NFC card on the ACTIVE
     * membership row. When the cross-membership flag is ON and the active row has
     * none, falls back to the person's other linked memberships (NFC possession is
     * identity-level, EXEMPT from biometric consent — product decision).
     */
    private boolean hasActiveNfcCard(UUID userId) {
        List<NfcCard> activeCards = nfcCardRepository.findByUserIdAndIsActiveTrue(userId);
        if (!activeCards.isEmpty()) {
            return true;
        }
        return crossMembershipNfcEnabled && hasCrossMembershipActiveNfcCard(userId);
    }

    /**
     * Cross-membership resolution: whether the person ({@code identity_id}) holds
     * an active NFC card under ANY linked membership OTHER than the active one.
     * Uses the controlled native-bypass read (the {@code nfc_cards → users} join is
     * not scoped by the Hibernate tenant filter). Audit-logs each cross-identity
     * match. Returns false (and logs nothing) when the flag is OFF, the user has no
     * identity, or no sibling card exists.
     */
    private boolean hasCrossMembershipActiveNfcCard(UUID userId) {
        UUID identityId = userJpaRepository.findIdentityIdById(userId).orElse(null);
        UUID requestingTenantId = userJpaRepository.findTenantIdById(userId).orElse(null);
        if (identityId == null || requestingTenantId == null) {
            return false;
        }
        boolean found = nfcCardRepository
                .existsActiveCardForIdentityExcludingTenant(identityId, requestingTenantId);
        if (found) {
            log.info("AUDIT: cross-identity NFC enrollment resolved — user {} (tenant {}) "
                    + "treated as NFC-enrolled via a sibling membership of identity {}",
                    userId, requestingTenantId, identityId);
        }
        return found;
    }
}
