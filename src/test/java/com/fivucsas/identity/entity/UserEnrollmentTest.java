package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link UserEnrollment} score lifecycle.
 *
 * <p>P1-3: the web FACE flow records quality/liveness scores via
 * {@code recordScores(...)} during the /enroll step, then finalizes the row with
 * the 2-arg {@code completeEnrollment(data)} → 3-arg overload with NULL scores.
 * Completion must PRESERVE the previously-recorded scores, not null them out.
 */
class UserEnrollmentTest {

    private UserEnrollment pendingFaceEnrollment() {
        return UserEnrollment.builder()
                .authMethodType(AuthMethodType.FACE)
                .status(EnrollmentStatus.PENDING)
                .build();
    }

    @Test
    void completeEnrollment_WithNullScores_PreservesRecordedScores() {
        // given — scores recorded during the /enroll step (the FACE flow order)
        UserEnrollment e = pendingFaceEnrollment();
        e.recordScores(new BigDecimal("0.9000"), new BigDecimal("0.8000"));

        // when — the 2-arg /complete delegates to (data, null, null)
        e.completeEnrollment("{}", null, null);

        // then — completion finalizes status but PRESERVES the recorded scores
        // (this was the P1-3 bug: scores were being nulled at completion)
        assertThat(e.getStatus()).isEqualTo(EnrollmentStatus.ENROLLED);
        assertThat(e.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.9000"));
        assertThat(e.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.8000"));
    }

    @Test
    void completeEnrollment_WithNonNullScores_SetsThem() {
        // given — a fresh row with no recorded scores
        UserEnrollment e = pendingFaceEnrollment();

        // when — the "complete WITH scores" caller passes real values
        e.completeEnrollment("{}", new BigDecimal("0.7000"), new BigDecimal("0.6000"));

        // then
        assertThat(e.getStatus()).isEqualTo(EnrollmentStatus.ENROLLED);
        assertThat(e.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.7000"));
        assertThat(e.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.6000"));
    }

    @Test
    void completeEnrollment_WithPartialScores_OverridesOnlyNonNull() {
        // given — both scores previously recorded
        UserEnrollment e = pendingFaceEnrollment();
        e.recordScores(new BigDecimal("0.9000"), new BigDecimal("0.8000"));

        // when — completion supplies a new quality but no liveness
        e.completeEnrollment("{}", new BigDecimal("0.9500"), null);

        // then — quality overridden, liveness preserved
        assertThat(e.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.9500"));
        assertThat(e.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.8000"));
    }

    @Test
    void recordScores_OnlyOverridesNonNullArguments() {
        UserEnrollment e = pendingFaceEnrollment();
        e.recordScores(new BigDecimal("0.5000"), new BigDecimal("0.4000"));

        // a later partial record (e.g. VOICE has no liveness) must not wipe liveness
        e.recordScores(new BigDecimal("0.6000"), null);

        assertThat(e.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.6000"));
        assertThat(e.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.4000"));
    }
}
