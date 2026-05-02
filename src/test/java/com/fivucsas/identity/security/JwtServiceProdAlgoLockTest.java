package com.fivucsas.identity.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AUDIT_2026-04-28_SECURITY.md SEC-P1 #3: when the {@code prod} profile
 * is active, JwtService.assertProdAlgoIsRs256 MUST fail-fast if the
 * configured default-algo is anything other than RS256. Closes the
 * silent-fallback risk where a stray env var or misconfigured deploy
 * could have prod minting HS512 tokens.
 */
@DisplayName("JwtService — prod profile RS256 lock (SEC-P1 #3)")
class JwtServiceProdAlgoLockTest {

    private static final String TEST_SECRET =
            "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZy1mb3ItaHMyNTYtYWxnb3JpdGhtLXNlY3VyaXR5LXJlcXVpcmVtZW50cw==";

    @Test
    @DisplayName("prod active + algo=HS512 -> startup fails")
    void prodWithHs512ShouldThrow() {
        JwtService service = newService(profile("prod"));
        ReflectionTestUtils.setField(service, "defaultAlgo", "HS512");

        assertThatThrownBy(service::assertProdAlgoIsRs256)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("MUST sign with RS256");
    }

    @Test
    @DisplayName("prod active + algo=RS256 -> boots cleanly")
    void prodWithRs256ShouldPass() {
        JwtService service = newService(profile("prod"));
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");

        assertThatCode(service::assertProdAlgoIsRs256).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("dev profile + algo=HS512 -> assertion is a no-op (dev keeps HS512)")
    void devProfileShouldNotEnforceRs256() {
        JwtService service = newService(profile("dev"));
        ReflectionTestUtils.setField(service, "defaultAlgo", "HS512");

        assertThatCode(service::assertProdAlgoIsRs256).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("no active profile -> assertion is a no-op (test/CI default)")
    void noActiveProfileShouldNotEnforceRs256() {
        JwtService service = newService(new MockEnvironment());
        ReflectionTestUtils.setField(service, "defaultAlgo", "HS512");

        assertThatCode(service::assertProdAlgoIsRs256).doesNotThrowAnyException();
    }

    private static JwtService newService(MockEnvironment env) {
        JwtSecretProvider hmac = mock(JwtSecretProvider.class);
        when(hmac.getSecret()).thenReturn(TEST_SECRET);
        RsaKeyProvider rsa = JwtAlgoTestSupport.newRsaKeyProvider();
        HsKeyRegistry registry = JwtAlgoTestSupport.newHsKeyRegistry(hmac);
        JwtService svc = new JwtService(registry, rsa, env);
        ReflectionTestUtils.setField(svc, "jwtExpiration", 900_000L);
        return svc;
    }

    private static MockEnvironment profile(String name) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(name);
        return env;
    }
}
