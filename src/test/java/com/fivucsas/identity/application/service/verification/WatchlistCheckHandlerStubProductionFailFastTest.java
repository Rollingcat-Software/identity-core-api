package com.fivucsas.identity.application.service.verification;

import com.fivucsas.identity.application.service.verification.handlers.WatchlistCheckHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Regression test for P0-#3 (INVESTIGATION_MASTER_2026-05-07.md):
 * {@link WatchlistCheckHandler} is a hard-coded "always cleared" mock. Before this fix
 * it was an unconditional {@code @Component} — so any KYC/AML flow including the
 * {@code WATCHLIST_CHECK} step would silently false-pass in production with no real
 * sanctions provider wired.
 *
 * <p>The fix: {@code @Profile("dev")} on the handler. This test is the ratchet that
 * prevents anyone from removing that annotation without explicitly noticing.
 *
 * <p>Two assertions:
 * <ol>
 *   <li>Under the {@code dev} profile the bean IS registered (existing dev/test
 *       flows that exercise WATCHLIST_CHECK keep working).</li>
 *   <li>Under the {@code prod} profile the bean is NOT registered, so any attempt
 *       to look it up via the registry surfaces an explicit
 *       {@link UnsupportedOperationException} — no silent mock in prod.</li>
 * </ol>
 *
 * <p>The test boots a tiny standalone context that only scans the handler package, so
 * it does not depend on a database, JWT keys, or any other prod-profile secrets.
 */
@DisplayName("WatchlistCheckHandler — stub fails fast in prod (P0-#3)")
class WatchlistCheckHandlerStubProductionFailFastTest {

    @Test
    @DisplayName("dev profile -> WatchlistCheckHandler bean IS registered")
    void devProfileRegistersHandler() {
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
            ctx.getEnvironment().setActiveProfiles("dev");
            ctx.register(WatchlistCheckHandler.class);
            ctx.refresh();

            assertThat(ctx.getBeansOfType(WatchlistCheckHandler.class))
                    .as("dev profile MUST keep the stub available so existing fixtures/tests work")
                    .hasSize(1);
        }
    }

    @Test
    @DisplayName("prod profile -> WatchlistCheckHandler bean is NOT registered (no silent mock in prod)")
    void prodProfileDoesNotRegisterHandler() {
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
            ctx.getEnvironment().setActiveProfiles("prod");
            ctx.register(WatchlistCheckHandler.class);
            ctx.refresh();

            assertThat(ctx.getBeansOfType(WatchlistCheckHandler.class))
                    .as("prod profile MUST NOT register the always-clears mock — KYC/AML safety")
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("default (no profile) -> WatchlistCheckHandler bean is NOT registered")
    void defaultProfileDoesNotRegisterHandler() {
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
            // Intentionally do NOT activate the dev profile.
            ctx.register(WatchlistCheckHandler.class);
            ctx.refresh();

            assertThat(ctx.getBeansOfType(WatchlistCheckHandler.class))
                    .as("absence of dev profile MUST NOT register the mock — fail closed")
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("registry semantics: missing handler surfaces UnsupportedOperationException")
    void registryThrowsForMissingHandler() {
        // Sanity-check the contract that downstream code relies on: when the handler is
        // not registered (i.e. prod), the registry surfaces an explicit error rather than
        // returning null or silently continuing.
        VerificationStepHandlerRegistry registry =
                new VerificationStepHandlerRegistry(java.util.List.of());
        registry.init();

        assertThatThrownBy(() -> registry.getHandler("WATCHLIST_CHECK"))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("WATCHLIST_CHECK");
    }
}
