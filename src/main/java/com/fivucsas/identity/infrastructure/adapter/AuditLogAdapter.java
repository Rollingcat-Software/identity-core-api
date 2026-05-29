package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.infrastructure.audit.AuditEscape;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Infrastructure adapter for audit logging.
 *
 * Persists audit log entries to the database via AuditLogRepository.
 * Uses REQUIRES_NEW propagation to ensure audit entries are committed
 * even when the calling transaction rolls back (e.g., failed login).
 *
 * Following principles:
 * - Adapter Pattern: Adapts domain events to persistence
 * - Dependency Inversion: Application defines port, infrastructure implements
 * - Single Responsibility: Only handles audit log persistence
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLogAdapter implements AuditLogPort {

    /**
     * Well-known "system" sentinel tenant UUID used for audit rows that are
     * truly cross-tenant / pre-authentication (failed-login attempts, PKCE
     * failures, /oauth2/token errors, scheduled jobs).
     *
     * <p>V59 (2026-05-11) backfilled historical NULL rows with this value and
     * the writer below now stamps it on new rows where the tenant cannot be
     * resolved. The constant intentionally does NOT correspond to a real row
     * in the {@code tenants} table — it is a logical marker. Admin views that
     * want to filter it out (per-tenant audit view) compare against this
     * literal; root-admin views surface it as "system".
     *
     * <p>See {@code src/main/resources/db/migration/V59__backfill_audit_logs_tenant_id.sql}
     * and SENIOR_DB_REVIEW_2026-05-04 §Appendix C.</p>
     */
    public static final UUID SYSTEM_TENANT_ID =
            UUID.fromString("00000000-0000-0000-0000-000000000000");

    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public void logUserRegistered(String userId, String email, String ipAddress) {
        log.info("AUDIT: User registered - userId={}, email={}, ip={}", userId, email, ipAddress);
        saveAuditLog("USER_CREATED", "USER", userId, true, ipAddress,
                Map.of("email", email));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logUserAuthenticated(String userId, String email, String ipAddress, String userAgent) {
        log.info("AUDIT: User authenticated — method: PASSWORD, userId={}, email={}, ip={}, userAgent={}",
                userId, email, ipAddress, userAgent);
        saveAuditLog("USER_LOGIN", "USER", userId, true, ipAddress, userAgent,
                Map.of("email", email, "method", "PASSWORD"));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logUserAuthenticated(String userId, String email, String ipAddress, String userAgent, String oauthClientName) {
        log.info("AUDIT: User authenticated — method: PASSWORD, oauthClient: {}, userId={}, email={}, ip={}, userAgent={}",
                oauthClientName, userId, email, ipAddress, userAgent);
        saveAuditLog("USER_LOGIN", "USER", userId, true, ipAddress, userAgent,
                Map.of("email", email, "method", "PASSWORD", "oauthClient", oauthClientName));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logAuthenticationFailed(String email, String ipAddress, String reason) {
        log.warn("AUDIT: Login failed — email={}, reason={}, ip={}", email, reason, ipAddress);
        // T4-C (2026-05-11): try to resolve tenant from the email so the
        // row is visible to that tenant's admin. Falls back to the system
        // sentinel inside saveAuditLog when the email is unknown (genuine
        // attacker probe). Email-based resolution can never identify the
        // user (we still pass userId=null so MFA correlation works), but
        // the tenant binding gives tenant admins visibility into attack
        // attempts targeting their users.
        UUID tenantFromEmail = resolveTenantIdByEmail(email);
        saveAuditLogWithTenant("FAILED_LOGIN_ATTEMPT", "USER", null, false, ipAddress,
                null, Map.of("email", email, "reason", reason), tenantFromEmail);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logUserLoggedOut(String userId, String email) {
        log.info("AUDIT: User logged out — userId={}, email={}", userId, email);
        saveAuditLog("USER_LOGOUT", "USER", userId, true, null,
                Map.of("email", email));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logBiometricEnrollment(String userId, boolean success) {
        log.info("AUDIT: Biometric enrollment — userId={}, success={}", userId, success);
        saveAuditLog("BIOMETRIC_ENROLLMENT", "BIOMETRIC", userId, success, null, Map.of());
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logBiometricVerification(String userId, boolean success) {
        log.info("AUDIT: Biometric verification — userId={}, success={}", userId, success);
        saveAuditLog("BIOMETRIC_VERIFICATION", "BIOMETRIC", userId, success, null, Map.of());
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSecurityEvent(String userId, String eventType, String ipAddress, String details) {
        log.info("AUDIT: Security event — userId={}, type={}, ip={}, details={}", userId, eventType, ipAddress, details);
        saveAuditLog(eventType, "SECURITY", userId, true, ipAddress,
                Map.of("details", details != null ? details : ""));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTenantManagementEvent(String actorUserId, String eventType,
                                         String tenantId, String details) {
        log.info("AUDIT: Tenant management event — type={}, actor={}, tenant={}, details={}",
                eventType, actorUserId, tenantId, details);
        UUID resolvedTenantId = parseUuidOrNull(tenantId);
        saveAuditLogWithActorAndResource(eventType, "TENANT", actorUserId, tenantId,
                true, null, null,
                details != null ? Map.of("details", details) : Map.of(),
                resolvedTenantId);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logMfaStepCompleted(String userId, String method, int stepCurrent, int stepTotal,
                                     String ipAddress, String userAgent) {
        log.info("AUDIT: MFA step completed — method: {}, step: {}/{}, userId={}, ip={}, userAgent={}",
                method, stepCurrent, stepTotal, userId, ipAddress, userAgent);
        saveAuditLog("MFA_STEP_COMPLETED", "AUTH", userId, true, ipAddress, userAgent,
                Map.of("method", method, "stepCurrent", stepCurrent, "stepTotal", stepTotal));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logMfaStepFailed(String userId, String method, String reason,
                                  String ipAddress, String userAgent) {
        log.warn("AUDIT: MFA step failed — method: {}, reason: {}, userId={}, ip={}, userAgent={}",
                method, reason, userId, ipAddress, userAgent);
        saveAuditLog("MFA_STEP_FAILED", "AUTH", userId, false, ipAddress, userAgent,
                Map.of("method", method, "reason", reason));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logMfaComplete(String userId, List<String> amrValues,
                                String ipAddress, String userAgent) {
        log.info("AUDIT: MFA complete — methods: {}, userId={}, ip={}, userAgent={}",
                amrValues, userId, ipAddress, userAgent);
        saveAuditLog("MFA_COMPLETE", "AUTH", userId, true, ipAddress, userAgent,
                Map.of("amr", amrValues));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTwoFactorFailed(String userId, String method, String reason,
                                    String ipAddress, String userAgent) {
        log.warn("AUDIT: 2FA failed — method: {}, reason: {}, userId={}, ip={}, userAgent={}",
                method, reason, userId, ipAddress, userAgent);
        saveAuditLog("TWO_FACTOR_FAILED", "AUTH", userId, false, ipAddress, userAgent,
                Map.of("method", method, "reason", reason));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTwoFactorVerified(String userId, String method,
                                      String ipAddress, String userAgent) {
        log.info("AUDIT: 2FA verified — method: {}, userId={}, ip={}, userAgent={}",
                method, userId, ipAddress, userAgent);
        saveAuditLog("TWO_FACTOR_VERIFIED", "AUTH", userId, true, ipAddress, userAgent,
                Map.of("method", method));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logPkceFailure(String clientId, String actorIp, String failureReason) {
        // Phase D5a — never include code_verifier or code_challenge here. The
        // metadata Map below is what surfaces in tenant audit-log views; if a
        // verifier value lands here, every brute-force guess is replayed back
        // to anyone with audit-log read on the tenant.
        log.warn("AUDIT: PKCE failure — clientId={}, ip={}, reason={}",
                clientId, actorIp, failureReason);
        Map<String, Object> metadata = new java.util.LinkedHashMap<>();
        metadata.put("clientId", clientId != null ? clientId : "");
        metadata.put("failureReason", failureReason != null ? failureReason : "UNKNOWN");
        saveAuditLog("PKCE_FAILURE", "OAUTH2", null, false, actorIp, null, metadata);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logNfcDocumentVerified(String userId, String documentNumberMasked,
                                       String issuingCountry, String mrzFormat,
                                       boolean checksumValid,
                                       String ipAddress, String userAgent) {
        // T2-A — never persist the full document number. The masked form is
        // last-4-chars and is built by the controller before it ever reaches
        // this adapter. The audit row still carries enough context (issuing
        // country, MRZ format, success bit) for SOC analysts to spot anomalous
        // sources without exposing PII.
        String action = checksumValid
                ? "NFC_DOCUMENT_VERIFIED"
                : "NFC_DOCUMENT_VERIFICATION_FAILED";
        log.info("AUDIT: NFC document {} — userId={}, country={}, format={}, masked={}, ip={}",
                checksumValid ? "verified" : "verification failed",
                userId, issuingCountry, mrzFormat, documentNumberMasked, ipAddress);
        Map<String, Object> metadata = new java.util.LinkedHashMap<>();
        metadata.put("documentNumberMasked",
                documentNumberMasked != null ? documentNumberMasked : "");
        metadata.put("issuingCountry",
                issuingCountry != null ? issuingCountry : "");
        metadata.put("mrzFormat", mrzFormat != null ? mrzFormat : "");
        metadata.put("checksumValid", checksumValid);
        saveAuditLog(action, "NFC_DOCUMENT", userId, checksumValid,
                ipAddress, userAgent, metadata);
    }

    private void saveAuditLog(String action, String resourceType, String userId,
                              boolean success, String ipAddress, Map<String, Object> metadata) {
        saveAuditLog(action, resourceType, userId, success, ipAddress, null, metadata);
    }

    private void saveAuditLog(String action, String resourceType, String userId,
                              boolean success, String ipAddress, String userAgent, Map<String, Object> metadata) {
        saveAuditLogWithTenant(action, resourceType, userId, success, ipAddress, userAgent, metadata, null);
    }

    /**
     * Overload used by anonymous-context emitters (failed login, PKCE
     * failure) that can resolve the tenant out-of-band (e.g. by email or
     * by oauth2 client) BEFORE this method runs. The supplied
     * {@code preResolvedTenantId} short-circuits the userId-based lookup;
     * if it is {@code null} the standard fallback chain
     * (userId → user-row lookup → SYSTEM_TENANT_ID) still applies.
     *
     * <p>The contract was previously that NULL tenant was acceptable for
     * anonymous events. V59 (2026-05-11) introduced the
     * {@link #SYSTEM_TENANT_ID} sentinel so audit rows are never NULL —
     * see {@code resolveTenantId} below.</p>
     */
    private void saveAuditLogWithTenant(String action, String resourceType, String userId,
                                        boolean success, String ipAddress, String userAgent,
                                        Map<String, Object> metadata, UUID preResolvedTenantId) {
        try {
            UUID rawId = userId != null ? UUID.fromString(userId) : null;
            // audit_logs.user_id is an FK→users. Several callers pass a NON-user
            // id here (e.g. tenant CRUD / email-domain CRUD pass the tenant id),
            // which violated audit_logs_user_id_fkey AT COMMIT — and because the
            // violation surfaces at the REQUIRES_NEW tx boundary (after this
            // try-block), the surrounding try/catch never caught it, so the whole
            // business operation 500'd + rolled back (observed repeatedly
            // 2026-05-29). Defensively null the FK column when the id is not a
            // real (non-deleted) user, but KEEP the original id as resourceId
            // (resource_id has no FK) so the audited resource is still recorded.
            UUID userUuid = (rawId != null && userRepository.existsById(rawId)) ? rawId : null;
            UUID tenantUuid = preResolvedTenantId != null
                    ? preResolvedTenantId
                    : resolveTenantId(userUuid);

            AuditLog auditLog = AuditLog.builder()
                    // SECURITY_REVIEW_2026-05-01 §P2-1: action / resourceType
                    // are static literals at every current call site, but
                    // escape them defense-in-depth so the contract is uniform
                    // — any future caller wiring a user-controlled action name
                    // (e.g. plugin event types) inherits the escape.
                    .action(AuditEscape.escape(action))
                    .resourceType(AuditEscape.escape(resourceType))
                    .tenantId(tenantUuid)
                    .userId(userUuid)
                    .resourceId(rawId)
                    .success(success)
                    .ipAddress(ipAddress)
                    // userAgent and metadata can contain user-supplied data
                    // (browser-reported UA strings, supplied display names, etc.).
                    // Escape on the way in so a downstream renderer that drops
                    // its escaping can never produce executable HTML from an
                    // audit row. JSONB-encoded structured values pass through
                    // unchanged via escapeMetadata's type-check.
                    .userAgent(AuditEscape.escape(userAgent))
                    .metadata(escapeMetadata(metadata))
                    .build();

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to persist audit log: action={}, error={}", action, e.getMessage(), e);
        }
    }

    /**
     * Writes an audit row with a SEPARATE actor and resource — the correct
     * shape for "admin X did Y to resource Z" events (e.g. tenant management).
     *
     * <p>Modeled on {@link #saveAuditLogWithTenant} but distinguishes the
     * {@code user_id} (acting admin FK) from the {@code resource_id} (the
     * managed entity), which the single-id {@code saveAuditLog*} helpers cannot
     * do — there the one id is forced into both columns.</p>
     *
     * <ul>
     *   <li>{@code actorUserId} → parsed to a UUID and stamped on {@code user_id}
     *       ONLY when it is a real, existing user (same {@code existsById} FK
     *       guard as {@link #saveAuditLogWithTenant}); otherwise {@code user_id}
     *       is null, so a non-user / null actor never violates
     *       {@code audit_logs_user_id_fkey}.</li>
     *   <li>{@code resourceId} → parsed to a UUID into {@code resource_id}
     *       ({@code resource_id} has no FK). A malformed value is nulled rather
     *       than dropping the whole row.</li>
     *   <li>{@code tenant_id} ← {@code preResolvedTenantId} when supplied,
     *       else the actor's resolved tenant.</li>
     * </ul>
     *
     * <p>Keeps all the same escaping ({@link AuditEscape}) and the outer
     * try/catch that logs-and-swallows, so an audit failure never breaks the
     * business operation.</p>
     */
    private void saveAuditLogWithActorAndResource(String action, String resourceType,
                                                  String actorUserId, String resourceId,
                                                  boolean success, String ipAddress, String userAgent,
                                                  Map<String, Object> metadata, UUID preResolvedTenantId) {
        try {
            UUID actorUuid = parseUuidOrNull(actorUserId);
            // Same FK guard as saveAuditLogWithTenant: only a real (non-deleted)
            // user lands in the user_id FK column; everything else is nulled so
            // the audit row never violates audit_logs_user_id_fkey at commit.
            UUID userUuid = (actorUuid != null && userRepository.existsById(actorUuid)) ? actorUuid : null;
            // resource_id has no FK — a bad parse must not drop the whole row.
            UUID resourceUuid = parseUuidOrNull(resourceId);
            UUID tenantUuid = preResolvedTenantId != null
                    ? preResolvedTenantId
                    : resolveTenantId(userUuid);

            AuditLog auditLog = AuditLog.builder()
                    .action(AuditEscape.escape(action))
                    .resourceType(AuditEscape.escape(resourceType))
                    .tenantId(tenantUuid)
                    .userId(userUuid)
                    .resourceId(resourceUuid)
                    .success(success)
                    .ipAddress(ipAddress)
                    .userAgent(AuditEscape.escape(userAgent))
                    .metadata(escapeMetadata(metadata))
                    .build();

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to persist audit log: action={}, error={}", action, e.getMessage(), e);
        }
    }

    /**
     * Parses a UUID string, returning {@code null} for null/blank/malformed
     * input instead of throwing. Used for the {@code resource_id} (no FK, so a
     * bad value must not abort the whole audit write) and the
     * {@code preResolvedTenantId} derivation in tenant-management events.
     */
    private static UUID parseUuidOrNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Returns a copy of {@code metadata} with all {@link String} values
     * HTML-escaped. Non-string values (numbers, lists, nested maps) pass
     * through unchanged — the JSONB encoder handles their representation
     * and they don't carry HTML-injection risk in their primitive form.
     */
    private Map<String, Object> escapeMetadata(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return metadata;
        }
        Map<String, Object> out = new java.util.LinkedHashMap<>(metadata.size());
        for (Map.Entry<String, Object> e : metadata.entrySet()) {
            out.put(e.getKey(), AuditEscape.escapeIfString(e.getValue()));
        }
        return out;
    }

    /**
     * Resolves the tenant_id to stamp on an audit row.
     *
     * <p>Background: tenant-admin's {@code /api/v1/audit-logs} endpoint filters
     * by {@code tenant_id = X}. Audit rows with NULL tenant_id are invisible to
     * every tenant admin, even though they describe activity inside a tenant.
     * V46 (2026-04-25) backfilled user-scoped NULLs; V59 (2026-05-11) backfilled
     * anonymous-event NULLs with the {@link #SYSTEM_TENANT_ID} sentinel.</p>
     *
     * <p>Resolution rules (T4-C, 2026-05-11):</p>
     * <ul>
     *   <li>If a {@code userId} is supplied, look up the user's tenant_id via
     *       {@link UserRepository#findTenantIdById}. This covers USER_LOGIN,
     *       USER_LOGOUT, MFA_*, BIOMETRIC_*, USER_CREATED, etc.</li>
     *   <li>If no {@code userId} is supplied, or the user lookup returns
     *       empty / throws (deleted user, transient DB error), return
     *       {@link #SYSTEM_TENANT_ID} — the well-known sentinel for
     *       cross-tenant / system rows. This guarantees the column is
     *       never NULL, which is the prerequisite for a future NOT NULL
     *       constraint (P2 follow-up post-soak).</li>
     * </ul>
     */
    private UUID resolveTenantId(UUID userId) {
        if (userId == null) {
            return SYSTEM_TENANT_ID;
        }
        try {
            return userRepository.findTenantIdById(userId).orElse(SYSTEM_TENANT_ID);
        } catch (Exception e) {
            log.warn("Failed to resolve tenant_id for audit row userId={}: {}", userId, e.getMessage());
            return SYSTEM_TENANT_ID;
        }
    }

    /**
     * Best-effort lookup of a tenant_id from an email. Used by
     * {@link #logAuthenticationFailed} so that a failed-login audit row can be
     * filed under the targeted user's tenant — making the row visible to that
     * tenant's admin (rather than invisible behind the system sentinel).
     *
     * <p>Returns {@code null} when the email is null/blank or no user matches,
     * in which case {@link #saveAuditLogWithTenant} falls through to
     * {@link #resolveTenantId} which yields {@link #SYSTEM_TENANT_ID}. Never
     * throws — exceptions are swallowed and logged.</p>
     */
    private UUID resolveTenantIdByEmail(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        try {
            return userRepository.findByEmail(email)
                    .map(u -> u.getTenantId() != null ? u.getTenantId().getValue() : null)
                    .orElse(null);
        } catch (Exception e) {
            log.warn("Failed to resolve tenant_id for audit row by email={}: {}", email, e.getMessage());
            return null;
        }
    }
}
