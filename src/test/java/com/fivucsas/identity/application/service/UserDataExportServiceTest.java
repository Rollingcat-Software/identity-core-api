package com.fivucsas.identity.application.service;

import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.repository.AuthSessionRepository;
import com.fivucsas.identity.repository.OAuth2ClientRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.VerificationSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link UserDataExportService} (GDPR Art. 20 / KVKK).
 *
 * <p>F14 (security review): the {@code voiceEnrollments} section was hardcoded
 * to an empty list, so a user's voice-enrollment metadata never appeared in
 * their data export. These tests assert that VOICE enrollment metadata IS now
 * surfaced (without raw embedding vectors, which live in biometric_db).</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("UserDataExportService — F14 GDPR voice export")
class UserDataExportServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private UserEnrollmentRepository userEnrollmentRepository;
    @Mock private AuthSessionRepository authSessionRepository;
    @Mock private AuditLogRepository auditLogRepository;
    @Mock private VerificationSessionRepository verificationSessionRepository;
    @Mock private OAuth2ClientRepository oauth2ClientRepository;

    @InjectMocks
    private UserDataExportService service;

    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();

        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.isAdmin()).thenReturn(false);
        when(user.getTenant()).thenReturn(null);
        when(user.getRoleNames()).thenReturn(java.util.Set.of());
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        // Empty out the sections we are not asserting on.
        for (AuthSessionStatus s : AuthSessionStatus.values()) {
            when(authSessionRepository.findAllByUserIdAndStatus(eq(userId), eq(s)))
                    .thenReturn(List.of());
        }
        Page<com.fivucsas.identity.entity.AuditLog> emptyAuditPage =
                new PageImpl<>(List.of());
        when(auditLogRepository.findByUserIdOrderByCreatedAtDesc(eq(userId), any()))
                .thenReturn(emptyAuditPage);
        when(verificationSessionRepository.findAllByUserIdOrderByCreatedAtDesc(userId))
                .thenReturn(List.of());
    }

    @Test
    @DisplayName("exportUserData → voiceEnrollments contains the user's VOICE enrollment metadata (F14)")
    @SuppressWarnings("unchecked")
    void exportUserData_includesVoiceEnrollments() {
        UserEnrollment voice = enrollment(AuthMethodType.VOICE,
                new BigDecimal("0.9100"), new BigDecimal("0.8800"));
        UserEnrollment face = enrollment(AuthMethodType.FACE, null, null);
        when(userEnrollmentRepository.findAllByUserId(userId))
                .thenReturn(List.of(voice, face));

        Map<String, Object> bundle = service.exportUserData(userId);

        List<Map<String, Object>> voiceSection =
                (List<Map<String, Object>>) bundle.get("voiceEnrollments");

        assertThat(voiceSection).hasSize(1);
        Map<String, Object> entry = voiceSection.get(0);
        assertThat(entry.get("authMethodType")).isEqualTo("VOICE");
        assertThat(entry.get("status")).isEqualTo("ENROLLED");
        assertThat(entry.get("qualityScore")).isEqualTo("0.9100");
        assertThat(entry.get("livenessScore")).isEqualTo("0.8800");
        // Raw embedding vector must never be in scope.
        assertThat(entry).doesNotContainKey("embedding");
        assertThat(entry).doesNotContainKey("enrollmentData");
    }

    @Test
    @DisplayName("exportUserData → voiceEnrollments is empty when the user has no VOICE enrollment")
    @SuppressWarnings("unchecked")
    void exportUserData_voiceEmpty_whenNoVoiceEnrollment() {
        UserEnrollment face = enrollment(AuthMethodType.FACE, null, null);
        when(userEnrollmentRepository.findAllByUserId(userId))
                .thenReturn(List.of(face));

        Map<String, Object> bundle = service.exportUserData(userId);

        List<Map<String, Object>> voiceSection =
                (List<Map<String, Object>>) bundle.get("voiceEnrollments");
        assertThat(voiceSection).isEmpty();
    }

    @Test
    @DisplayName("exportUserData → throws UserNotFoundException for an unknown user")
    void exportUserData_unknownUser_throws() {
        UUID unknown = UUID.randomUUID();
        when(userRepository.findById(unknown)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.exportUserData(unknown))
                .isInstanceOf(UserNotFoundException.class);
    }

    private UserEnrollment enrollment(AuthMethodType method, BigDecimal quality, BigDecimal liveness) {
        UserEnrollment e = mock(UserEnrollment.class);
        when(e.getId()).thenReturn(UUID.randomUUID());
        when(e.getAuthMethodType()).thenReturn(method);
        when(e.getStatus()).thenReturn(EnrollmentStatus.ENROLLED);
        when(e.getQualityScore()).thenReturn(quality);
        when(e.getLivenessScore()).thenReturn(liveness);
        when(e.getEnrolledAt()).thenReturn(Instant.parse("2026-01-01T00:00:00Z"));
        return e;
    }
}
