package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers {@link SoftDeletePurgeJob}:
 *
 * <ul>
 *   <li>feature flag off → no-op (dry-run still returns the candidate list so operators
 *       can preview before enabling)</li>
 *   <li>feature flag on → purges users older than 30 days</li>
 *   <li>users within 30-day window are not candidates</li>
 *   <li>dry-run returns candidate count without mutating rows</li>
 *   <li>scheduled entry point respects feature flag</li>
 *   <li>USER_HARD_PURGED audit event emitted per deletion</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SoftDeletePurgeJob Tests (GDPR Art. 17)")
class SoftDeletePurgeJobTest {

    @Mock private UserRepository userRepository;
    @Mock private AuditLogPort auditLogPort;
    @Mock private EntityManager entityManager;
    @Mock private Query query;

    @InjectMocks
    private SoftDeletePurgeJob job;

    @BeforeEach
    void resetFlag() {
        // Default: disabled, matches app.purge.softDelete.enabled=false in application.yml
        ReflectionTestUtils.setField(job, "enabled", false);
        // EntityManager is used by purgeBatch() to set the V53 trigger bypass GUC
        // (`SET LOCAL app.allow_hard_delete = 'on'`). @InjectMocks does not populate
        // @PersistenceContext-annotated fields, so wire it explicitly via reflection.
        // Stub leniently — only the enabled path actually calls it, and Mockito
        // strict-stubbing would otherwise complain.
        ReflectionTestUtils.setField(job, "entityManager", entityManager);
        org.mockito.Mockito.lenient().when(entityManager.createNativeQuery(anyString())).thenReturn(query);
        org.mockito.Mockito.lenient().when(query.executeUpdate()).thenReturn(0);
    }

    // ── feature flag off ────────────────────────────────────────────────

    @Test
    @DisplayName("purge() with feature flag disabled is a no-op and skips repository")
    void purge_disabled_isNoOp() {
        SoftDeletePurgeJob.PurgeResult result = job.purge();

        assertThat(result.purged()).isZero();
        assertThat(result.purgedIds()).isEmpty();
        verify(userRepository, never()).findPurgeCandidates(any(), any());
        verify(userRepository, never()).delete(any());
        verify(auditLogPort, never()).logSecurityEvent(any(), eq("USER_HARD_PURGED"), any(), any());
    }

    @Test
    @DisplayName("runScheduled() skips entirely when feature flag is disabled")
    void runScheduled_disabled_skips() {
        job.runScheduled();
        verify(userRepository, never()).findPurgeCandidates(any(), any());
    }

    // ── feature flag on ─────────────────────────────────────────────────

    @Test
    @DisplayName("purge() deletes users soft-deleted more than 30 days ago and emits audit")
    void purge_enabled_deletesOldUsers() {
        ReflectionTestUtils.setField(job, "enabled", true);

        User oldUser = User.builder()
            .id(UUID.randomUUID())
            .email("old@example.com")
            .passwordHash("$2a$10$hash")
            .firstName("Old")
            .lastName("Gone")
            .build();
        oldUser.softDelete();
        // Backdate deletedAt to 40 days ago via reflection (no public setter)
        ReflectionTestUtils.setField(oldUser, "deletedAt",
            Instant.now().minus(Duration.ofDays(40)));

        when(userRepository.findPurgeCandidates(any(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(oldUser)))
            .thenReturn(Page.empty());
        when(userRepository.hardDeleteById(oldUser.getId())).thenReturn(1);

        SoftDeletePurgeJob.PurgeResult result = job.purge();

        assertThat(result.purged()).isEqualTo(1);
        assertThat(result.purgedIds()).containsExactly(oldUser.getId());
        // Native hard-delete bypasses @SQLDelete (which would otherwise loop forever
        // re-stamping the same soft-deleted rows). See UserRepository.hardDeleteById.
        verify(userRepository).hardDeleteById(oldUser.getId());
        verify(userRepository, never()).delete(any());
        verify(auditLogPort).logSecurityEvent(
            any(),  // actor=null for system scheduler
            eq("USER_HARD_PURGED"),
            any(),
            anyString());
    }

    @Test
    @DisplayName("purge() does NOT re-discover the same row across cycles (no infinite loop)")
    void purge_doesNotInfiniteLoopOnSameSoftDeletedRow() {
        ReflectionTestUtils.setField(job, "enabled", true);

        UUID userId = UUID.randomUUID();
        User oldUser = User.builder()
            .id(userId)
            .email("loop@example.com")
            .passwordHash("$2a$10$hash")
            .firstName("Loop")
            .lastName("Guard")
            .build();
        oldUser.softDelete();
        ReflectionTestUtils.setField(oldUser, "deletedAt",
            Instant.now().minus(Duration.ofDays(40)));

        // First page returns the candidate, then empty — simulates the row being
        // hard-deleted out of the candidate set on the next call.
        when(userRepository.findPurgeCandidates(any(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(oldUser)))
            .thenReturn(Page.empty());
        when(userRepository.hardDeleteById(userId)).thenReturn(1);

        SoftDeletePurgeJob.PurgeResult result = job.purge();

        // hardDeleteById called exactly once — no soft-delete rewrite recurrence.
        verify(userRepository, times(1)).hardDeleteById(userId);
        assertThat(result.purged()).isEqualTo(1);
    }

    @Test
    @DisplayName("purge() ignores users soft-deleted within the 30-day window (repository responsibility)")
    void purge_enabled_skipsRecentlyDeleted() {
        ReflectionTestUtils.setField(job, "enabled", true);

        // Repository enforces the cutoff in its JPQL query; when nothing matches,
        // the job does nothing — no deletes, no audit events.
        when(userRepository.findPurgeCandidates(any(), any(Pageable.class)))
            .thenReturn(Page.empty());

        SoftDeletePurgeJob.PurgeResult result = job.purge();

        assertThat(result.purged()).isZero();
        verify(userRepository, never()).delete(any());
        verify(auditLogPort, never()).logSecurityEvent(any(), eq("USER_HARD_PURGED"), any(), any());
    }

    @Test
    @DisplayName("purge() stops once a short batch (<BATCH_SIZE) is returned")
    void purge_stopsAfterShortBatch() {
        ReflectionTestUtils.setField(job, "enabled", true);

        User u1 = buildPurgeCandidate();
        User u2 = buildPurgeCandidate();
        // First call returns 2 users (< batch size of 100) → job exits after first batch.
        when(userRepository.findPurgeCandidates(any(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(u1, u2)));
        // Hard delete returns 1 row affected for both candidates.
        when(userRepository.hardDeleteById(any(UUID.class))).thenReturn(1);

        SoftDeletePurgeJob.PurgeResult result = job.purge();

        assertThat(result.purged()).isEqualTo(2);
        verify(userRepository, times(1)).findPurgeCandidates(any(), any(Pageable.class));
        verify(auditLogPort, times(2))
            .logSecurityEvent(any(), eq("USER_HARD_PURGED"), any(), anyString());
    }

    // ── dry-run ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("dryRun() returns candidate IDs without deleting rows (feature flag ignored)")
    void dryRun_returnsCandidatesWithoutDeleting() {
        // Feature flag stays false — dry-run must work for operators before enabling
        User cand = buildPurgeCandidate();
        Page<User> page = new PageImpl<>(List.of(cand), Pageable.ofSize(1000), 1);
        when(userRepository.findPurgeCandidates(any(), any(Pageable.class))).thenReturn(page);

        SoftDeletePurgeJob.DryRunResult result = job.dryRun();

        assertThat(result.candidateCount()).isEqualTo(1);
        assertThat(result.candidateIds()).containsExactly(cand.getId());
        verify(userRepository, never()).delete(any());
        verify(auditLogPort, never()).logSecurityEvent(any(), eq("USER_HARD_PURGED"), any(), any());
    }

    @Test
    @DisplayName("dryRun() reports the correct count when multiple candidates exist")
    void dryRun_reportsCount() {
        User c1 = buildPurgeCandidate();
        User c2 = buildPurgeCandidate();
        User c3 = buildPurgeCandidate();
        Page<User> page = new PageImpl<>(List.of(c1, c2, c3), Pageable.ofSize(1000), 3);
        when(userRepository.findPurgeCandidates(any(), any(Pageable.class))).thenReturn(page);

        SoftDeletePurgeJob.DryRunResult result = job.dryRun();

        assertThat(result.candidateCount()).isEqualTo(3);
        assertThat(result.candidateIds()).hasSize(3);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private User buildPurgeCandidate() {
        User u = User.builder()
            .id(UUID.randomUUID())
            .email("purge-me@example.com")
            .passwordHash("$2a$10$hash")
            .firstName("Purge")
            .lastName("Me")
            .build();
        u.softDelete();
        ReflectionTestUtils.setField(u, "deletedAt",
            Instant.now().minus(Duration.ofDays(45)));
        return u;
    }
}
