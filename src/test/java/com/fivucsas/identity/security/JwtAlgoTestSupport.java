package com.fivucsas.identity.security;

import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Test helpers for BE-H1 dual-algorithm JWT coexistence and the HS-key registry
 * (T3.C, parallel-verify rotation).
 */
final class JwtAlgoTestSupport {

    private JwtAlgoTestSupport() {}

    static RsaKeyProvider newRsaKeyProvider() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        RsaKeyProvider p = new RsaKeyProvider(env);
        ReflectionTestUtils.setField(p, "kid", RsaKeyProvider.DEFAULT_KID);
        p.initialize();
        return p;
    }

    /**
     * Builds an {@link HsKeyRegistry} backed by {@code secretProvider} and the
     * given {@code env}, defaulting to a single active kid
     * ({@link HsKeyRegistry#DEFAULT_ACTIVE_KID}). Mirrors the production
     * single-key topology that pre-dated the registry.
     */
    static HsKeyRegistry newHsKeyRegistry(JwtSecretProvider secretProvider, Environment env) {
        HsKeyRegistry r = new HsKeyRegistry(secretProvider, env);
        ReflectionTestUtils.setField(r, "activeHsKid", HsKeyRegistry.DEFAULT_ACTIVE_KID);
        ReflectionTestUtils.setField(r, "retiredHsKidsCsv", "");
        r.initialize();
        return r;
    }

    /**
     * Convenience overload for callers that don't need an explicit
     * {@link Environment} (most legacy tests).
     */
    static HsKeyRegistry newHsKeyRegistry(JwtSecretProvider secretProvider) {
        return newHsKeyRegistry(secretProvider, new MockEnvironment());
    }
}
