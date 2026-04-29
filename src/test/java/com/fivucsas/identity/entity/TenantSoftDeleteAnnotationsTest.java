package com.fivucsas.identity.entity;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EDGE-P1 #5 — Static guard test for the Tenant entity's soft-delete contract.
 *
 * <p>If a future refactor accidentally drops {@code @SQLDelete} or
 * {@code @SQLRestriction} from the Tenant entity, the {@code tenants} table
 * would once again be vulnerable to a hard {@code DELETE} that CASCADE-wipes
 * ~10 dependent tables. This test makes that regression visible at unit-test
 * speed without needing a running database.
 */
@DisplayName("Tenant entity — soft-delete annotations are present")
class TenantSoftDeleteAnnotationsTest {

    @Test
    void tenantEntity_hasSqlDeleteAnnotation_thatRewritesToSoftUpdate() {
        SQLDelete annotation = Tenant.class.getAnnotation(SQLDelete.class);

        assertThat(annotation)
            .as("@SQLDelete must be present on Tenant entity to prevent "
                + "hard delete from cascade-wiping ~10 child tables")
            .isNotNull();
        assertThat(annotation.sql())
            .as("@SQLDelete SQL must be a soft UPDATE on deleted_at")
            .containsIgnoringCase("UPDATE tenants")
            .containsIgnoringCase("deleted_at");
    }

    @Test
    void tenantEntity_hasSqlRestriction_filteringSoftDeletedRows() {
        SQLRestriction annotation = Tenant.class.getAnnotation(SQLRestriction.class);

        assertThat(annotation)
            .as("@SQLRestriction must be present so JPA finds skip "
                + "soft-deleted rows by default")
            .isNotNull();
        assertThat(annotation.value())
            .as("@SQLRestriction must filter on deleted_at IS NULL")
            .containsIgnoringCase("deleted_at IS NULL");
    }

    @Test
    void tenantEntity_hasDeletedAtField_mappedToDbColumn() throws Exception {
        Field deletedAt = Tenant.class.getDeclaredField("deletedAt");

        assertThat(deletedAt.getType()).isEqualTo(Instant.class);

        jakarta.persistence.Column col = deletedAt.getAnnotation(jakarta.persistence.Column.class);
        assertThat(col).as("deletedAt must be mapped").isNotNull();
        assertThat(col.name()).isEqualTo("deleted_at");
    }

    @Test
    void tenantBuilder_canSetDeletedAt_andIsDeletedReturnsTrue() {
        Instant now = Instant.now();
        Tenant deleted = Tenant.builder()
            .name("Acme")
            .slug("acme")
            .contactEmail("ops@acme.test")
            .deletedAt(now)
            .build();
        Tenant alive = Tenant.builder()
            .name("Beta")
            .slug("beta")
            .contactEmail("ops@beta.test")
            .build();

        assertThat(deleted.isDeleted()).isTrue();
        assertThat(deleted.getDeletedAt()).isEqualTo(now);
        assertThat(alive.isDeleted()).isFalse();
        assertThat(alive.getDeletedAt()).isNull();
    }
}
