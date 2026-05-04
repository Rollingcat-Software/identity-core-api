package com.fivucsas.identity.entity;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P0-PROD 2026-05-04 — Static guard test for the GuestInvitation `metadata`
 * column's JSON binding.
 *
 * <p>{@code columnDefinition = "jsonb"} only affects DDL. Without
 * {@code @JdbcTypeCode(SqlTypes.JSON)} Hibernate binds {@code String} as
 * varchar at runtime, which PostgreSQL rejects against the real {@code jsonb}
 * column with {@code expression is of type character varying}. The bug
 * surfaced as "could not invite guest" 500s — see prod api logs
 * {@code 2026-05-04 12:29:50 SqlExceptionHelper Batch entry 0 ... metadata}.
 * </p>
 */
@DisplayName("GuestInvitation entity — jsonb metadata binding contract")
class GuestInvitationJsonbBindingTest {

    @Test
    void metadataField_hasJdbcTypeCodeJson_soHibernateBindsAsJsonNotVarchar() throws Exception {
        Field metadata = GuestInvitation.class.getDeclaredField("metadata");

        JdbcTypeCode annotation = metadata.getAnnotation(JdbcTypeCode.class);

        assertThat(annotation)
            .as("@JdbcTypeCode(SqlTypes.JSON) must be present on `metadata` so "
                + "Hibernate binds the String as jsonb at runtime, not varchar")
            .isNotNull();
        assertThat(annotation.value())
            .as("Bind type must be SqlTypes.JSON")
            .isEqualTo(SqlTypes.JSON);
    }

    @Test
    void metadataField_defaultsToEmptyJsonObject_soNullBindIsImpossible() {
        GuestInvitation invitation = GuestInvitation.builder().build();

        assertThat(invitation.getMetadata())
            .as("metadata builder default must be a valid JSON literal so the row "
                + "is never inserted with the column DEFAULT '{}'::jsonb getting "
                + "overridden by an explicit NULL varchar bind")
            .isEqualTo("{}");
    }
}
