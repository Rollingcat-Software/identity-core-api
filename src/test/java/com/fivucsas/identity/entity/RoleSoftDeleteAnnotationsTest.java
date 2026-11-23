package com.fivucsas.identity.entity;

import org.hibernate.annotations.SQLRestriction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * #242 — static guard test for the Role entity's soft-delete read contract.
 *
 * <p>{@link Role#softDelete()} only stamps {@code deleted_at} (and clears
 * {@code is_active}); there is no {@code @SQLDelete} because deletion is a
 * service-level operation. Without {@code @SQLRestriction}, the read side keeps
 * returning tombstoned rows from {@code findById}, {@code findAll},
 * {@code findByTenantId} and every join-to-Role / lazy-proxy path, which leaks
 * deleted roles into admin lists and can surface a used-but-deleted role as a
 * 500 in new code.</p>
 *
 * <p>Runs at unit-test speed (reflection, no database), matching
 * {@code UserSoftDeleteAnnotationsTest} and {@code TenantSoftDeleteAnnotationsTest}.</p>
 */
@DisplayName("Role entity — soft-delete annotations are present")
class RoleSoftDeleteAnnotationsTest {

    @Test
    void roleEntity_hasSqlRestriction_filteringSoftDeletedRows() {
        SQLRestriction annotation = Role.class.getAnnotation(SQLRestriction.class);

        assertThat(annotation)
            .as("@SQLRestriction must be present on Role so every entity read "
                + "skips soft-deleted roles (#242)")
            .isNotNull();
        assertThat(annotation.value())
            .as("@SQLRestriction must filter on deleted_at IS NULL")
            .containsIgnoringCase("deleted_at IS NULL");
    }

    @Test
    void roleEntity_hasDeletedAtField_mappedToDbColumn() throws Exception {
        Field deletedAt = Role.class.getDeclaredField("deletedAt");

        assertThat(deletedAt.getType()).isEqualTo(Instant.class);

        jakarta.persistence.Column col = deletedAt.getAnnotation(jakarta.persistence.Column.class);
        assertThat(col).as("deletedAt must be mapped").isNotNull();
        assertThat(col.name()).isEqualTo("deleted_at");
    }

    @Test
    void roleSoftDelete_stampsDeletedAtAndDeactivates() {
        Role role = Role.builder()
                .name("TENANT_ADMIN")
                .isSystemRole(false)
                .active(true)
                .build();

        assertThat(role.isDeleted()).isFalse();

        role.softDelete();

        assertThat(role.isDeleted()).isTrue();
        assertThat(role.getDeletedAt()).isNotNull();
        assertThat(role.isActive()).isFalse();
    }
}