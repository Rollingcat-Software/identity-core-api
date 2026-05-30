package com.fivucsas.identity.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins {@link RsaKeyProvider}'s profile-dependent key sourcing.
 *
 * <p>The Testcontainers integration-test suite (required tenant-isolation CI gate,
 * P1-1) boots the full Spring context under the {@code integration} profile but
 * the CI job injects no {@code JWT_RSA_*} env vars — so the provider MUST
 * auto-generate an ephemeral pair there, exactly like {@code dev}/{@code test}.
 * {@code prod} must still fail fast.</p>
 */
@DisplayName("RsaKeyProvider — profile-dependent ephemeral key generation")
class RsaKeyProviderProfileTest {

    private static RsaKeyProvider provider(String profile) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(profile);
        return new RsaKeyProvider(env);
    }

    @Test
    @DisplayName("integration profile auto-generates an ephemeral RSA pair (no env keys required)")
    void integrationProfileAutoGenerates() {
        RsaKeyProvider p = provider("integration");
        p.initialize();
        assertThat(p.getPrivateKey()).isNotNull();
        assertThat(p.getPublicKey()).isNotNull();
    }

    @Test
    @DisplayName("test + dev profiles still auto-generate")
    void testAndDevAutoGenerate() {
        RsaKeyProvider t = provider("test");
        t.initialize();
        assertThat(t.getPrivateKey()).isNotNull();

        RsaKeyProvider d = provider("dev");
        d.initialize();
        assertThat(d.getPrivateKey()).isNotNull();
    }

    @Test
    @DisplayName("prod profile still fail-fasts when no RSA keys are configured")
    void prodProfileFailsFast() {
        RsaKeyProvider p = provider("prod");
        assertThatThrownBy(p::initialize)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("RSA JWT key pair");
    }
}
