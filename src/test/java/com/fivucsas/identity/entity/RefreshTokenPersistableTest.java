package com.fivucsas.identity.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Persistable;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P0-PROD 2026-05-04 — RefreshToken must implement Persistable<UUID> with an
 * explicit "is this row new?" flag, otherwise Spring Data's default
 * {@code id-is-null} heuristic treats every pre-assigned-id RefreshToken as
 * already-persistent and routes save() through merge() instead of persist(),
 * which causes the detached-merge path to throw StaleObjectStateException on
 * every mint after PR #56's wire-format change.
 *
 * <p>Audit-log evidence (2026-05-04 06:34 — 06:38 UTC, ahabgu@gmail.com):
 * 6 consecutive MFA_STEP_FAILED rows with reason
 * {@code orchestration-error: ObjectOptimisticLockingFailureException}.
 * Stack trace points at {@code RefreshTokenService.createRefreshTokenInFamily}
 * line 91 → {@code SimpleJpaRepository.save} → {@code DefaultMergeEventListener.entityIsDetached}.
 * </p>
 */
@DisplayName("RefreshToken — Persistable<UUID> contract guard")
class RefreshTokenPersistableTest {

    @Test
    void refreshToken_implementsPersistableUUID() {
        assertThat(Persistable.class)
            .as("RefreshToken must implement Persistable<UUID> so a pre-assigned "
                + "id is still treated as a new row by Spring Data save()")
            .isAssignableFrom(RefreshToken.class);
    }

    @Test
    void freshlyBuiltToken_isNew() {
        RefreshToken token = RefreshToken.builder()
            .id(UUID.randomUUID())
            .token("placeholder-wire-token")
            .familyId(UUID.randomUUID())
            .expiryDate(Instant.now().plusSeconds(3600))
            .build();

        assertThat(token.isNew())
            .as("A builder-constructed RefreshToken must report isNew() == true "
                + "even when its id is pre-assigned, so save() routes to persist()")
            .isTrue();
    }

    @Test
    void postPersistOrPostLoad_flipsNewEntityFalse() throws Exception {
        RefreshToken token = RefreshToken.builder()
            .id(UUID.randomUUID())
            .token("placeholder")
            .familyId(UUID.randomUUID())
            .expiryDate(Instant.now().plusSeconds(3600))
            .build();

        assertThat(token.isNew()).isTrue();

        // Simulate the JPA lifecycle callback firing.
        Method markPersistent = RefreshToken.class.getDeclaredMethod("markPersistent");
        markPersistent.setAccessible(true);
        markPersistent.invoke(token);

        assertThat(token.isNew())
            .as("After @PostPersist / @PostLoad, isNew() must be false so future "
                + "in-place updates correctly route through merge()")
            .isFalse();
    }
}
