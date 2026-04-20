package com.fivucsas.identity.security;

import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Test helpers for BE-H1 dual-algorithm JWT coexistence.
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
}
