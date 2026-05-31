package com.fivucsas.identity.application.service.mfa;

import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.dto.AvailableMfaMethod;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AvailableMethodsResolverTest {

    private final AvailableMethodsResolver resolver = new AvailableMethodsResolver();

    private AuthMethod method(AuthMethodType type, boolean requiresEnrollment) {
        return AuthMethod.builder()
                .id(UUID.randomUUID())
                .type(type)
                .name(type.name())
                .category(AuthMethodCategory.BASIC)
                .platforms(List.of("WEB"))
                .requiresEnrollment(requiresEnrollment)
                .build();
    }

    private Map<String, AvailableMfaMethod> byType(List<AvailableMfaMethod> ms) {
        return ms.stream().collect(Collectors.toMap(AvailableMfaMethod::getMethodType, Function.identity()));
    }

    @Test
    void passwordEnrolledByHash_notByEnrollmentHealth() {
        // The bug this guards: at layer 2+, PASSWORD showed "not enrolled" because the
        // builder relied on enrollment-health (which has no PASSWORD row). The generic
        // rule is: PASSWORD enrolled iff the user has a password hash.
        AuthFlowStep step = mock(AuthFlowStep.class);
        when(step.getAvailableMethods()).thenReturn(List.of(
                method(AuthMethodType.PASSWORD, true),
                method(AuthMethodType.FACE, true),
                method(AuthMethodType.EMAIL_OTP, false)));

        List<AvailableMfaMethod> result = resolver.build(
                step, /*hasPassword*/ true, Map.of(AuthMethodType.FACE, true), null);

        assertThat(result).hasSize(3); // FULL set, nothing filtered
        Map<String, AvailableMfaMethod> m = byType(result);
        assertThat(m.get("PASSWORD").isEnrolled()).isTrue();    // by password hash (no health row)
        assertThat(m.get("FACE").isEnrolled()).isTrue();        // by enrollment health
        assertThat(m.get("EMAIL_OTP").isEnrolled()).isTrue();   // no enrollment required
    }

    @Test
    void passwordNotEnrolled_whenNoHash_andUnenrolledBiometricNotEnrolled() {
        AuthFlowStep step = mock(AuthFlowStep.class);
        when(step.getAvailableMethods()).thenReturn(List.of(
                method(AuthMethodType.PASSWORD, true),
                method(AuthMethodType.HARDWARE_KEY, true)));

        List<AvailableMfaMethod> result = resolver.build(step, /*hasPassword*/ false, Map.of(), null);

        Map<String, AvailableMfaMethod> m = byType(result);
        assertThat(m.get("PASSWORD").isEnrolled()).isFalse();      // no password hash
        assertThat(m.get("HARDWARE_KEY").isEnrolled()).isFalse();  // requires enrollment, none present
        assertThat(result).hasSize(2);                             // full set, nothing filtered
    }

    @Test
    void preferredMarkerHonoured() {
        AuthFlowStep step = mock(AuthFlowStep.class);
        when(step.getAvailableMethods()).thenReturn(List.of(method(AuthMethodType.TOTP, true)));
        List<AvailableMfaMethod> result = resolver.build(step, false, Map.of(AuthMethodType.TOTP, true), "TOTP");
        assertThat(result.get(0).isPreferred()).isTrue();
    }

    @Test
    void hasPassword_helper() {
        assertThat(AvailableMethodsResolver.hasPassword("$2a$10$abc")).isTrue();
        assertThat(AvailableMethodsResolver.hasPassword("")).isFalse();
        assertThat(AvailableMethodsResolver.hasPassword("  ")).isFalse();
        assertThat(AvailableMethodsResolver.hasPassword(null)).isFalse();
    }
}
