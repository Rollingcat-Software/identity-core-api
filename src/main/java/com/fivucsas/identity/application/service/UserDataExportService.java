package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.UserDataExportUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.repository.AuthSessionRepository;
import com.fivucsas.identity.repository.OAuth2ClientRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.VerificationSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * GDPR Art. 20 / KVKK data-portability service.
 *
 * <p>Gathers personal data from identity-core tables (users, user_enrollments, auth_sessions,
 * audit_logs, verification_sessions, oauth2_clients) into a single JSON-serialisable bundle.
 * Biometric face/voice embeddings stored in the separate {@code biometric_db} are out of scope
 * for this service — only enrollment metadata from {@code user_enrollments} (enrolled_at,
 * quality_score, liveness_score, auth method) is exposed.</p>
 *
 * <p>Exclusions (deliberate, industry norm):
 * <ul>
 *   <li>password_hash, two_factor_secret (BCrypt hash + TOTP seed)</li>
 *   <li>two_factor_backup_codes (treat as credentials)</li>
 *   <li>email/password-reset tokens (ephemeral credentials)</li>
 *   <li>raw embedding vectors from biometric-processor pgvector store (opaque security artefacts)</li>
 *   <li>WebAuthn credential private material (handled at registration-time)</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserDataExportService implements UserDataExportUseCase {

    /** Bump this when the response schema changes in a breaking way. */
    private static final String EXPORT_FORMAT_VERSION = "1.0";

    /** Cap per-section list sizes so one runaway user can't OOM the JVM. */
    private static final int MAX_AUDIT_LOG_ENTRIES = 10_000;

    private final UserRepository userRepository;
    private final UserEnrollmentRepository userEnrollmentRepository;
    private final AuthSessionRepository authSessionRepository;
    private final AuditLogRepository auditLogRepository;
    private final VerificationSessionRepository verificationSessionRepository;
    private final OAuth2ClientRepository oauth2ClientRepository;

    @Override
    public Map<String, Object> exportUserData(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("exportedAt", Instant.now().toString());
        bundle.put("exportFormatVersion", EXPORT_FORMAT_VERSION);
        bundle.put("user", serializeUser(user));
        bundle.put("enrollments", serializeEnrollments(userId));
        bundle.put("authFlows", serializeAuthSessions(userId));
        bundle.put("auditLogs", serializeAuditLogs(userId));
        bundle.put("verificationSessions", serializeVerificationSessions(userId));
        bundle.put("oauth2Clients", serializeOAuth2Clients(user));
        // Raw face/voice embedding VECTORS live in biometric_db (managed by
        // biometric-processor) and remain out of scope here. The per-method
        // enrollment METADATA (status, quality, liveness, timestamps) that
        // identity-core owns in user_enrollments IS in scope — F14 surfaces it
        // under the dedicated key GDPR consumers expect. Previously this was
        // hardcoded to an empty list, so voice enrollments never appeared in
        // the export.
        bundle.put("voiceEnrollments", serializeEnrollmentsForMethod(userId, AuthMethodType.VOICE));
        bundle.put("biometricEnrollments", List.of());
        return bundle;
    }

    private Map<String, Object> serializeUser(User u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", u.getId().toString());
        m.put("email", u.getEmail());
        m.put("firstName", u.getFirstName());
        m.put("lastName", u.getLastName());
        m.put("phoneNumber", u.getPhoneNumber());   // present only if user provided it
        m.put("idNumber", u.getIdNumber());
        m.put("address", u.getAddress());
        m.put("userType", u.getUserType() != null ? u.getUserType().name() : null);
        m.put("status", u.getStatus() != null ? u.getStatus().name() : null);
        m.put("emailVerified", u.isEmailVerified());
        m.put("phoneVerified", u.isPhoneVerified());
        m.put("identityVerified", u.isIdentityVerified());
        m.put("identityVerifiedAt", toStringOrNull(u.getIdentityVerifiedAt()));
        m.put("verificationLevel", u.getVerificationLevel() != null ? u.getVerificationLevel().name() : null);
        m.put("isBiometricEnrolled", u.isBiometricEnrolled());
        m.put("enrolledAt", toStringOrNull(u.getEnrolledAt()));
        m.put("lastLoginAt", toStringOrNull(u.getLastLoginAt()));
        m.put("lastLoginIp", u.getLastLoginIp());
        m.put("createdAt", toStringOrNull(u.getCreatedAt()));
        m.put("updatedAt", toStringOrNull(u.getUpdatedAt()));
        m.put("deletedAt", toStringOrNull(u.getDeletedAt()));
        m.put("tenantId", u.getTenant() != null ? u.getTenant().getId().toString() : null);
        m.put("tenantName", u.getTenant() != null ? u.getTenant().getName() : null);
        m.put("roles", u.getRoleNames());
        return m;
    }

    private List<Map<String, Object>> serializeEnrollments(UUID userId) {
        List<UserEnrollment> enrollments = userEnrollmentRepository.findAllByUserId(userId);
        return enrollments.stream()
            .map(this::serializeEnrollment)
            .toList();
    }

    /**
     * F14: per-method slice of a user's enrollments, used to surface biometric
     * enrollment metadata (e.g. VOICE) under its own export key. Raw embedding
     * vectors are NOT included — only the metadata identity-core owns in
     * {@code user_enrollments} (status, quality_score, liveness_score, timestamps).
     */
    private List<Map<String, Object>> serializeEnrollmentsForMethod(UUID userId, AuthMethodType method) {
        List<UserEnrollment> enrollments = userEnrollmentRepository.findAllByUserId(userId);
        return enrollments.stream()
            .filter(e -> e.getAuthMethodType() == method)
            .map(this::serializeEnrollment)
            .toList();
    }

    private Map<String, Object> serializeEnrollment(UserEnrollment e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", e.getId() != null ? e.getId().toString() : null);
        m.put("authMethodType", e.getAuthMethodType() != null ? e.getAuthMethodType().name() : null);
        m.put("status", e.getStatus() != null ? e.getStatus().name() : null);
        m.put("qualityScore", e.getQualityScore() != null ? e.getQualityScore().toPlainString() : null);
        m.put("livenessScore", e.getLivenessScore() != null ? e.getLivenessScore().toPlainString() : null);
        m.put("enrolledAt", toStringOrNull(e.getEnrolledAt()));
        m.put("expiresAt", toStringOrNull(e.getExpiresAt()));
        m.put("revokedAt", toStringOrNull(e.getRevokedAt()));
        m.put("createdAt", toStringOrNull(e.getCreatedAt()));
        // enrollmentData intentionally omitted — may contain keyed secrets per method
        return m;
    }

    private List<Map<String, Object>> serializeAuthSessions(UUID userId) {
        // Aggregate across all statuses so the export captures both active and completed flows.
        // Existing repository only exposes findAllByUserIdAndStatus, so we iterate enum values.
        List<AuthSession> sessions = new java.util.ArrayList<>();
        for (com.fivucsas.identity.domain.model.auth.AuthSessionStatus status
                : com.fivucsas.identity.domain.model.auth.AuthSessionStatus.values()) {
            sessions.addAll(authSessionRepository.findAllByUserIdAndStatus(userId, status));
        }
        return sessions.stream()
            .map(s -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", s.getId() != null ? s.getId().toString() : null);
                m.put("status", s.getStatus() != null ? s.getStatus().name() : null);
                m.put("operationType", s.getOperationType() != null ? s.getOperationType().name() : null);
                m.put("startedAt", toStringOrNull(s.getStartedAt()));
                m.put("completedAt", toStringOrNull(s.getCompletedAt()));
                m.put("expiresAt", toStringOrNull(s.getExpiresAt()));
                m.put("ipAddress", s.getIpAddress());
                // session token / secret fields deliberately NOT exposed
                return m;
            })
            .toList();
    }

    private List<Map<String, Object>> serializeAuditLogs(UUID userId) {
        var page = auditLogRepository.findByUserIdOrderByCreatedAtDesc(
            userId, PageRequest.of(0, MAX_AUDIT_LOG_ENTRIES));
        return page.getContent().stream()
            .map(this::serializeAuditLog)
            .toList();
    }

    private Map<String, Object> serializeAuditLog(AuditLog a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId() != null ? a.getId().toString() : null);
        m.put("action", a.getAction());
        m.put("resourceType", a.getResourceType());
        m.put("resourceId", a.getResourceId() != null ? a.getResourceId().toString() : null);
        m.put("success", a.getSuccess());
        m.put("ipAddress", a.getIpAddress());
        m.put("userAgent", a.getEffectiveUserAgent());
        m.put("endpoint", a.getEndpoint());
        m.put("httpMethod", a.getHttpMethod());
        m.put("statusCode", a.getStatusCode());
        m.put("createdAt", toStringOrNull(a.getCreatedAt()));
        // old_values / new_values / metadata may contain other users' PII — strip by default
        return m;
    }

    private List<Map<String, Object>> serializeVerificationSessions(UUID userId) {
        List<VerificationSession> sessions = verificationSessionRepository.findAllByUserIdOrderByCreatedAtDesc(userId);
        return sessions.stream()
            .map(s -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", s.getId() != null ? s.getId().toString() : null);
                m.put("status", s.getStatus() != null ? s.getStatus().name() : null);
                m.put("startedAt", toStringOrNull(s.getStartedAt()));
                m.put("completedAt", toStringOrNull(s.getCompletedAt()));
                m.put("createdAt", toStringOrNull(s.getCreatedAt()));
                return m;
            })
            .toList();
    }

    private List<Map<String, Object>> serializeOAuth2Clients(User user) {
        // Only tenant admins / root see OAuth clients — they "own" the integration.
        // Non-admin users get an empty list (their tenant's clients are not "their" personal data).
        if (user.getTenant() == null || !user.isAdmin()) {
            return List.of();
        }
        List<OAuth2Client> clients =
            oauth2ClientRepository.findAllByTenantIdOrderByCreatedAtDesc(user.getTenant().getId());
        return clients.stream()
            .map(c -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", c.getId() != null ? c.getId().toString() : null);
                m.put("clientId", c.getClientId());
                m.put("clientName", c.getClientName());
                m.put("allowedScopes", c.getAllowedScopes());
                m.put("confidential", c.isConfidential());
                m.put("active", c.isActive());
                m.put("createdAt", toStringOrNull(c.getCreatedAt()));
                m.put("revokedAt", toStringOrNull(c.getRevokedAt()));
                // client_secret deliberately excluded
                return m;
            })
            .toList();
    }

    private static String toStringOrNull(Instant instant) {
        return instant == null ? null : instant.toString();
    }
}
