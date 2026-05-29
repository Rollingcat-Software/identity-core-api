package com.fivucsas.identity.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain (no-Docker) unit tests for the Phase 1 identity entities ({@link Identity},
 * {@link IdentityEmail}) and the {@link User} identity mapping. Verifies the
 * builder/getter contract, the raw read-only FK columns, and JPA-safe equality —
 * without booting Spring or a database (the persistence behaviour is covered by
 * {@code IdentityBackfillIT}, which is RUN_INTEGRATION-gated).
 */
class IdentityEntityTest {

    @Test
    void identity_builderDefaultsStatusActive() {
        Identity identity = Identity.builder()
                .displayName("Ahmet Abdullah")
                .build();

        assertThat(identity.getStatus()).isEqualTo("ACTIVE");
        assertThat(identity.getDisplayName()).isEqualTo("Ahmet Abdullah");
    }

    @Test
    void identity_equalityByIdAcrossProxyLikeInstances() {
        UUID id = UUID.randomUUID();
        Identity a = Identity.builder().id(id).build();
        Identity b = Identity.builder().id(id).build();
        Identity other = Identity.builder().id(UUID.randomUUID()).build();

        assertThat(a).isEqualTo(b);
        assertThat(a).isNotEqualTo(other);
        // transient (id == null) entities are equal only by reference
        assertThat(Identity.builder().build()).isNotEqualTo(Identity.builder().build());
    }

    @Test
    void identityEmail_buildsWithVerifiedFlagAndRawIdentityId() {
        UUID identityId = UUID.randomUUID();
        Identity identity = Identity.builder().id(identityId).build();
        Instant now = Instant.now();

        IdentityEmail email = IdentityEmail.builder()
                .identity(identity)
                .identityId(identityId)
                .email("ahabgu@gmail.com")
                .verified(true)
                .verifiedAt(now)
                .build();

        assertThat(email.getEmail()).isEqualTo("ahabgu@gmail.com");
        assertThat(email.isVerified()).isTrue();
        assertThat(email.getVerifiedAt()).isEqualTo(now);
        assertThat(email.getIdentity()).isSameAs(identity);
        // raw FK column readable without touching the association proxy
        assertThat(email.getIdentityId()).isEqualTo(identityId);
    }

    @Test
    void identityEmail_defaultsUnverified() {
        IdentityEmail email = IdentityEmail.builder()
                .email("x@example.com")
                .build();

        assertThat(email.isVerified()).isFalse();
        assertThat(email.getVerifiedAt()).isNull();
    }

    @Test
    void user_identityMappingAndRawIdentityIdReadable() {
        UUID identityId = UUID.randomUUID();
        Identity identity = Identity.builder().id(identityId).build();

        User user = User.builder()
                .email("ahabgu@gmail.com")
                .passwordHash("hash")
                .firstName("Ahmet")
                .lastName("Abdullah")
                .identity(identity)
                .identityId(identityId)
                .build();

        assertThat(user.getIdentity()).isSameAs(identity);
        // raw FK readable without initializing the lazy proxy (P1-4 idiom)
        assertThat(user.getIdentityId()).isEqualTo(identityId);
    }
}
