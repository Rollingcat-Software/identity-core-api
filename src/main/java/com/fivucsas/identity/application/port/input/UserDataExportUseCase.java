package com.fivucsas.identity.application.port.input;

import java.util.Map;
import java.util.UUID;

/**
 * Input port for exporting a user's personal data (GDPR Art. 20 / KVKK data portability).
 *
 * <p>Returns a bundle of personal data the controller holds about the user, structured as a
 * single JSON-serialisable {@link Map}. Raw biometric embeddings, password hashes, MFA
 * secrets and session tokens are deliberately excluded — those are either opaque security
 * artefacts (industry norm: Auth0, Okta exclude raw templates) or outright credentials.</p>
 *
 * <p>Called by {@code UserDataExportController}.</p>
 */
public interface UserDataExportUseCase {

    /**
     * Collects and returns the exportable personal data for the given user.
     *
     * @param userId target user's UUID
     * @return JSON-ready map with keys: exportedAt, exportFormatVersion, user, enrollments,
     *         authFlows, auditLogs, verificationSessions, oauth2Clients, voiceEnrollments,
     *         biometricEnrollments
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user not found
     */
    Map<String, Object> exportUserData(UUID userId);
}
