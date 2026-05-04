package com.fivucsas.identity.entity;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SENIOR_DB_REVIEW_2026-05-04 §P0-2 — Static guard test for the User entity's
 * soft-delete contract.
 *
 * <p>V53 ships a BEFORE-DELETE trigger that raises {@code restrict_violation}
 * on hard {@code DELETE FROM users}. Without {@code @SQLDelete} the JPA layer
 * keeps issuing real DELETEs that the trigger now rejects, surfacing as 5xx on
 * the admin user-delete path. The trigger is the safety net; this annotation
 * is the contract.</p>
 *
 * <p>{@code @SQLRestriction} also enforces the read-side half: every
 * entity-level query auto-filters {@code deleted_at IS NULL}, which closes
 * SENIOR_DB_REVIEW §P0-3 (9 {@code findBy*} methods leaking soft-deleted rows
 * into admin lists during the GDPR retention window).</p>
 */
@DisplayName("User entity — soft-delete annotations are present")
class UserSoftDeleteAnnotationsTest {

    @Test
    void userEntity_hasSqlDeleteAnnotation_thatRewritesToSoftUpdate() {
        SQLDelete annotation = User.class.getAnnotation(SQLDelete.class);

        assertThat(annotation)
            .as("@SQLDelete must be present on User entity — V53 trigger forbids "
                + "hard DELETE FROM users; without this annotation, JPA delete() = 5xx")
            .isNotNull();
        assertThat(annotation.sql())
            .as("@SQLDelete SQL must be a soft UPDATE on deleted_at + status + is_active")
            .containsIgnoringCase("UPDATE users")
            .containsIgnoringCase("deleted_at")
            .containsIgnoringCase("status")
            .containsIgnoringCase("is_active");
    }

    @Test
    void userEntity_hasSqlRestriction_filteringSoftDeletedRows() {
        SQLRestriction annotation = User.class.getAnnotation(SQLRestriction.class);

        assertThat(annotation)
            .as("@SQLRestriction must be present so all entity reads skip "
                + "soft-deleted rows during the GDPR retention window")
            .isNotNull();
        assertThat(annotation.value())
            .as("@SQLRestriction must filter on deleted_at IS NULL")
            .containsIgnoringCase("deleted_at IS NULL");
    }

    @Test
    void userEntity_hasDeletedAtField_mappedToDbColumn() throws Exception {
        Field deletedAt = User.class.getDeclaredField("deletedAt");

        assertThat(deletedAt.getType()).isEqualTo(Instant.class);

        jakarta.persistence.Column col = deletedAt.getAnnotation(jakarta.persistence.Column.class);
        assertThat(col).as("deletedAt must be mapped").isNotNull();
        assertThat(col.name()).isEqualTo("deleted_at");
    }

    @Test
    void userSoftDelete_marksDeletedAtAndDeactivates() {
        // The domain method softDelete() must do the same thing the SQL does,
        // so direct entity calls and JPA cascade DELETE both end in the same state.
        User u = User.builder().email("victim@example.test").firstName("V").lastName("X").build();

        assertThat(u.isSoftDeleted()).isFalse();

        u.softDelete();

        assertThat(u.isSoftDeleted()).isTrue();
        assertThat(u.getDeletedAt()).isNotNull();
        assertThat(u.getStatus()).isEqualTo(UserStatus.INACTIVE);
        assertThat(u.isActive()).isFalse();
    }
}
