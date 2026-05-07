package com.fivucsas.identity.application.service.verification;

import com.fivucsas.identity.application.service.verification.handlers.AddressProofHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Regression test for P1 hygiene 2026-05-07:
 * {@link AddressProofHandler} is a hard-coded "always pending review" mock —
 * it accepts any non-empty image, never actually stores it, never validates
 * the document, and never extracts an address. Before this fix it was an
 * unconditional {@code @Component} — so any KYC flow including the
 * {@code ADDRESS_PROOF} step would silently false-pass in production with no
 * real media storage or OCR provider wired.
 *
 * <p>The fix: {@code @Profile("dev")} on the handler. This test is the ratchet
 * that prevents anyone from removing that annotation without explicitly
 * noticing. Mirrors {@code WatchlistCheckHandlerStubProductionFailFastTest}
 * (P0-#3, api #81).
 *
 * <p>Three assertions:
 * <ol>
 *   <li>Under the {@code dev} profile the bean IS registered (existing dev/test
 *       fixtures that exercise ADDRESS_PROOF keep working).</li>
 *   <li>Under the {@code prod} profile the bean is NOT registered, so any
 *       attempt to look it up via the registry surfaces an explicit
 *       {@link UnsupportedOperationException} — no silent mock in prod.</li>
 *   <li>Default (no active profile) also does not register the bean — fail
 *       closed.</li>
 * </ol>
 *
 * <p>The test boots a tiny standalone context that only scans the handler
 * package, so it does not depend on a database, JWT keys, or any other
 * prod-profile secrets.
 */
@DisplayName("AddressProofHandler — stub fails fast in prod (P1 hygiene)")
class AddressProofHandlerProductionFailFastTest {

    @Test
    @DisplayName("dev profile -> AddressProofHandler bean IS registered")
    void devProfileRegistersHandler() {
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
            ctx.getEnvironment().setActiveProfiles("dev");
            ctx.register(AddressProofHandler.class);
            ctx.refresh();

            assertThat(ctx.getBeansOfType(AddressProofHandler.class))
                    .as("dev profile MUST keep the stub available so existing fixtures/tests work")
                    .hasSize(1);
        }
    }

    @Test
    @DisplayName("prod profile -> AddressProofHandler bean is NOT registered (no silent mock in prod)")
    void prodProfileDoesNotRegisterHandler() {
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
            ctx.getEnvironment().setActiveProfiles("prod");
            ctx.register(AddressProofHandler.class);
            ctx.refresh();

            assertThat(ctx.getBeansOfType(AddressProofHandler.class))
                    .as("prod profile MUST NOT register the always-stored mock — KYC safety")
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("default (no profile) -> AddressProofHandler bean is NOT registered")
    void defaultProfileDoesNotRegisterHandler() {
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext()) {
            // Intentionally do NOT activate the dev profile.
            ctx.register(AddressProofHandler.class);
            ctx.refresh();

            assertThat(ctx.getBeansOfType(AddressProofHandler.class))
                    .as("absence of dev profile MUST NOT register the mock — fail closed")
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("registry semantics: missing handler surfaces UnsupportedOperationException")
    void registryThrowsForMissingHandler() {
        // Sanity-check the contract that downstream code relies on: when the
        // handler is not registered (i.e. prod), the registry surfaces an
        // explicit error rather than returning null or silently continuing.
        VerificationStepHandlerRegistry registry =
                new VerificationStepHandlerRegistry(java.util.List.of());
        registry.init();

        assertThatThrownBy(() -> registry.getHandler("ADDRESS_PROOF"))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("ADDRESS_PROOF");
    }
}
