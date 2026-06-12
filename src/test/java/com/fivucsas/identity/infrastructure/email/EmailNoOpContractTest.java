package com.fivucsas.identity.infrastructure.email;

import com.fivucsas.identity.application.port.output.EmailServicePort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Bug 3 guard — the mail-disabled NO-OP adapters must implement EVERY method of
 * the email contracts they stand in for, so a {@code mail.enabled=false}
 * deployment can never hit an unimplemented method (guest invitation/revoke, OTP,
 * multi-locale, onboarding) at runtime.
 *
 * <p>Java already enforces this at compile time, but this test pins the
 * invariant against future interface growth: if a new method is added to
 * {@link EmailService} or {@link EmailServicePort} and only wired into the real
 * adapter, this reflection check fails fast instead of silently leaving the
 * no-op behind.</p>
 *
 * <p>There are TWO independent contracts: the infrastructure {@link EmailService}
 * (real {@link SmtpEmailService} / no-op {@link NoOpEmailService}) and the
 * application {@link EmailServicePort} (real {@code EmailServicePortAdapter} /
 * no-op {@code EmailServiceAdapter}). Both are checked here.</p>
 */
@DisplayName("Email no-op adapter contract (Bug 3)")
class EmailNoOpContractTest {

    private static Set<String> abstractMethodSignatures(Class<?> iface) {
        return Arrays.stream(iface.getMethods())
                .map(m -> m.getName() + Arrays.toString(m.getParameterTypes()))
                .collect(Collectors.toSet());
    }

    private static Set<String> concreteOverrideSignatures(Class<?> impl) {
        return Arrays.stream(impl.getMethods())
                .filter(m -> !Modifier.isAbstract(m.getModifiers()))
                .map(m -> m.getName() + Arrays.toString(m.getParameterTypes()))
                .collect(Collectors.toSet());
    }

    @Test
    @DisplayName("NoOpEmailService is concrete and covers every EmailService method")
    void noOpEmailServiceCoversEmailService() {
        assertThat(Modifier.isAbstract(NoOpEmailService.class.getModifiers())).isFalse();
        assertThat(concreteOverrideSignatures(NoOpEmailService.class))
                .containsAll(abstractMethodSignatures(EmailService.class));
        // Parity with the real implementation — both honour the same contract.
        assertThat(concreteOverrideSignatures(SmtpEmailService.class))
                .containsAll(abstractMethodSignatures(EmailService.class));
    }

    @Test
    @DisplayName("EmailServiceAdapter no-op is concrete and covers every EmailServicePort method")
    void noOpPortAdapterCoversEmailServicePort() {
        Class<?> noOpPort = com.fivucsas.identity.infrastructure.adapter.EmailServiceAdapter.class;
        assertThat(Modifier.isAbstract(noOpPort.getModifiers())).isFalse();
        assertThat(concreteOverrideSignatures(noOpPort))
                .containsAll(abstractMethodSignatures(EmailServicePort.class));
    }

    @Test
    @DisplayName("Calling every NoOpEmailService method when mail is disabled never throws")
    void noOpEmailServiceMethodsAreSafeToCall() {
        NoOpEmailService noOp = new NoOpEmailService();
        assertThatCode(() -> {
            noOp.sendOtp("a@b.com", "123456");
            noOp.sendOtp("a@b.com", "123456", OtpPurpose.LOGIN_VERIFICATION, "tr");
            noOp.sendGuestInvitation("a@b.com", "tok", java.time.Instant.now(),
                    java.time.Instant.now(), "msg", "Inviter", "Acme", "en");
            noOp.sendTenantOnboardingVerification("a@b.com", "Admin", "Acme", "tok");
        }).doesNotThrowAnyException();
    }
}
