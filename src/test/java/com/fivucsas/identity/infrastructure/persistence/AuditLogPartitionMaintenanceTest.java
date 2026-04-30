package com.fivucsas.identity.infrastructure.persistence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDate;
import java.time.YearMonth;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuditLogPartitionMaintenance}.
 *
 * <p>Verifies the three contracts that matter for production safety:
 * <ol>
 *   <li>The component asks Postgres to create the current month + LOOK_AHEAD_MONTHS
 *       additional months — no more, no less.</li>
 *   <li>The first day of each month is what's passed to
 *       {@code ensure_audit_logs_partition(date)} — the V41 helper expects
 *       a month-aligned date.</li>
 *   <li>Database errors during boot do not propagate (so a degraded DB
 *       can't crash-loop the pod over an advisory partition check).</li>
 * </ol>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditLogPartitionMaintenance")
class AuditLogPartitionMaintenanceTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private AuditLogPartitionMaintenance maintenance;

    @Test
    @DisplayName("ensureLookAhead issues CREATE check for current month + LOOK_AHEAD_MONTHS")
    void ensureLookAhead_callsHelperOncePerMonth() {
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), any(LocalDate.class)))
                .thenReturn(Boolean.FALSE);

        int created = maintenance.ensureLookAhead();

        // 1 (current month) + LOOK_AHEAD_MONTHS additional = 3 calls
        int expectedCalls = 1 + AuditLogPartitionMaintenance.LOOK_AHEAD_MONTHS;
        verify(jdbc, times(expectedCalls)).queryForObject(
                eq("SELECT ensure_audit_logs_partition(?)"),
                eq(Boolean.class),
                any(LocalDate.class));
        assertThat(created).isZero();   // helper returned false for every call
    }

    @Test
    @DisplayName("ensureLookAhead passes the first-of-month for each month in window")
    void ensureLookAhead_passesFirstOfMonth() {
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), any(LocalDate.class)))
                .thenReturn(Boolean.FALSE);

        maintenance.ensureLookAhead();

        ArgumentCaptor<LocalDate> dateCap = ArgumentCaptor.forClass(LocalDate.class);
        verify(jdbc, times(1 + AuditLogPartitionMaintenance.LOOK_AHEAD_MONTHS))
                .queryForObject(anyString(), eq(Boolean.class), dateCap.capture());

        List<LocalDate> dates = dateCap.getAllValues();
        // Each must be day-of-month = 1.
        assertThat(dates).allMatch(d -> d.getDayOfMonth() == 1);

        // Must be sequential months starting at YearMonth.now().
        YearMonth start = YearMonth.now();
        for (int i = 0; i < dates.size(); i++) {
            assertThat(dates.get(i))
                    .as("month index %d", i)
                    .isEqualTo(start.plusMonths(i).atDay(1));
        }
    }

    @Test
    @DisplayName("ensureMonth returns true when helper reports creation")
    void ensureMonth_returnsTrueOnCreation() {
        YearMonth target = YearMonth.now().plusMonths(1);
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), eq(target.atDay(1))))
                .thenReturn(Boolean.TRUE);

        boolean result = maintenance.ensureMonth(target);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("ensureMonth returns false when partition already exists")
    void ensureMonth_returnsFalseWhenAlreadyExists() {
        YearMonth target = YearMonth.now().plusMonths(1);
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), eq(target.atDay(1))))
                .thenReturn(Boolean.FALSE);

        boolean result = maintenance.ensureMonth(target);

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("ensureMonth swallows DB exceptions (boot must not crash on advisory check)")
    void ensureMonth_swallowsExceptions() {
        YearMonth target = YearMonth.now().plusMonths(1);
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), eq(target.atDay(1))))
                .thenThrow(new DataAccessResourceFailureException("DB unreachable"));

        // Should NOT throw — the post-construct path must never crash the pod.
        boolean result = maintenance.ensureMonth(target);

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("ensureLookAhead reports the count of newly created partitions")
    void ensureLookAhead_returnsCreatedCount() {
        // First call (current month) = already exists; second & third = created.
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), any(LocalDate.class)))
                .thenReturn(Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);

        int created = maintenance.ensureLookAhead();

        assertThat(created).isEqualTo(2);
    }
}
