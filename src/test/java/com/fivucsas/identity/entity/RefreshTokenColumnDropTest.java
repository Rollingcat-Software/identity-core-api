package com.fivucsas.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Transient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T4-D (2026-05-11): pins the post-V60 RefreshToken contract.
 *
 * <p>V60 dropped {@code refresh_tokens.token} (the plaintext column). The
 * Java field of the same name was retained for one-shot in-memory exposure of
 * the wire token at mint-time and is annotated {@link Transient} so JPA does
 * not try to map it. If a future refactor accidentally re-introduces a
 * {@link Column} annotation on this field, Hibernate metadata validation will
 * fail at boot (column does not exist) — but the failure mode is opaque, so
 * we pin the contract here.</p>
 *
 * <p>Also asserts that {@code token_secret_hash} is mapped as a persistent
 * column — the hashed secret IS the source of truth for refresh-token lookup
 * after V60.</p>
 */
@DisplayName("RefreshToken — post-V60 column mapping pin")
class RefreshTokenColumnDropTest {

    @Test
    @DisplayName("`token` field is @Transient (V60 dropped the plaintext column)")
    void tokenField_isTransient() throws NoSuchFieldException {
        Field token = RefreshToken.class.getDeclaredField("token");

        assertThat(token.getAnnotation(Transient.class))
                .as("RefreshToken.token must be @Transient post-V60 — see V60__drop_refresh_tokens_token_plaintext.sql")
                .isNotNull();
        assertThat(token.getAnnotation(Column.class))
                .as("RefreshToken.token must NOT carry @Column post-V60 — the column was dropped")
                .isNull();
    }

    @Test
    @DisplayName("`tokenSecretHash` field is mapped as a persistent column")
    void tokenSecretHashField_isPersistent() throws NoSuchFieldException {
        Field hash = RefreshToken.class.getDeclaredField("tokenSecretHash");

        Column col = hash.getAnnotation(Column.class);
        assertThat(col)
                .as("RefreshToken.tokenSecretHash must be @Column — it IS the source of truth post-V60")
                .isNotNull();
        assertThat(col.name()).isEqualTo("token_secret_hash");
        assertThat(hash.getAnnotation(Transient.class)).isNull();
    }

    @Test
    @DisplayName("RefreshTokenRepository no longer exposes findByToken(String) / existsByToken… queries [T4-D]")
    void repositoryDoesNotExposeDroppedQueries() {
        // Hibernate would fail at boot if these derived queries remained
        // (the underlying column is gone). We pin source-level absence so
        // a future refactor cannot silently re-introduce them.
        var methodNames = java.util.Arrays.stream(
                        com.fivucsas.identity.repository.RefreshTokenRepository.class.getDeclaredMethods())
                .map(java.lang.reflect.Method::getName)
                .toList();

        assertThat(methodNames)
                .as("findByToken(String) was the derived JPA query over the dropped plaintext column. Remove it; route through RefreshTokenService.findByToken which goes via id+hash.")
                .doesNotContain("findByToken");
        assertThat(methodNames)
                .as("existsByTokenAndIsRevokedFalse(String) referenced the dropped plaintext column.")
                .doesNotContain("existsByTokenAndIsRevokedFalse");
    }
}
