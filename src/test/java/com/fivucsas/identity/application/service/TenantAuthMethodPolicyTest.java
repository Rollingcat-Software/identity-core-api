package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.TenantAuthMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the SAFE / fail-open enforcement semantics. This gates
 * dashboard login, so the cases below pin the contract:
 *   - no configuration row  → ALLOWED  (today's default; never lock out)
 *   - explicit enabled=false → BLOCKED  (only when the kill-switch is ON)
 *   - explicit enabled=true  → ALLOWED
 *   - kill-switch OFF        → ALLOWED unconditionally (no lookup at all)
 */
@ExtendWith(MockitoExtension.class)
class TenantAuthMethodPolicyTest {

    @Mock private TenantAuthMethodRepositoryPort tenantAuthMethodRepository;

    // Enforcement ON by default for the contract tests below.
    private TenantAuthMethodPolicy policy;

    private final UUID tenantId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        policy = new TenantAuthMethodPolicy(tenantAuthMethodRepository, true);
    }

    private TenantAuthMethod row(AuthMethodType type, boolean enabled) {
        AuthMethod method = AuthMethod.builder()
                .id(UUID.randomUUID())
                .type(type)
                .name(type.name())
                .category(AuthMethodCategory.BASIC)
                .platforms(List.of("web"))
                .build();
        return TenantAuthMethod.builder()
                .id(UUID.randomUUID())
                .authMethod(method)
                .isEnabled(enabled)
                .build();
    }

    @Test
    void noRow_isAllowed() {
        when(tenantAuthMethodRepository.findByTenantIdAndType(tenantId, AuthMethodType.SMS_OTP))
                .thenReturn(Optional.empty());

        assertThat(policy.isLoginMethodAllowedForTenant(tenantId, AuthMethodType.SMS_OTP)).isTrue();
        assertThat(policy.isLoginMethodExplicitlyDisabled(tenantId, AuthMethodType.SMS_OTP)).isFalse();
    }

    @Test
    void explicitDisabledRow_isBlocked() {
        when(tenantAuthMethodRepository.findByTenantIdAndType(tenantId, AuthMethodType.SMS_OTP))
                .thenReturn(Optional.of(row(AuthMethodType.SMS_OTP, false)));

        assertThat(policy.isLoginMethodAllowedForTenant(tenantId, AuthMethodType.SMS_OTP)).isFalse();
        assertThat(policy.isLoginMethodExplicitlyDisabled(tenantId, AuthMethodType.SMS_OTP)).isTrue();
    }

    @Test
    void explicitEnabledRow_isAllowed() {
        when(tenantAuthMethodRepository.findByTenantIdAndType(tenantId, AuthMethodType.TOTP))
                .thenReturn(Optional.of(row(AuthMethodType.TOTP, true)));

        assertThat(policy.isLoginMethodAllowedForTenant(tenantId, AuthMethodType.TOTP)).isTrue();
    }

    @Test
    void nullTenant_failsOpenAllow() {
        assertThat(policy.isLoginMethodAllowedForTenant(null, AuthMethodType.PASSWORD)).isTrue();
    }

    @Test
    void lookupFailure_failsOpenAllow() {
        when(tenantAuthMethodRepository.findByTenantIdAndType(tenantId, AuthMethodType.FACE))
                .thenThrow(new RuntimeException("db down"));

        // A misconfigured/unavailable lookup must NEVER lock a tenant out.
        assertThat(policy.isLoginMethodAllowedForTenant(tenantId, AuthMethodType.FACE)).isTrue();
    }

    @Test
    void killSwitchOff_allowsEverythingWithoutLookup() {
        // app.auth.enforce-tenant-auth-methods=false → enforcement OFF. Even an
        // explicit is_enabled=false row is ignored (and the repo is never hit),
        // so the gate reverts to legacy "toggles are cosmetic" behaviour.
        TenantAuthMethodPolicy disabled =
                new TenantAuthMethodPolicy(tenantAuthMethodRepository, false);
        lenient().when(tenantAuthMethodRepository.findByTenantIdAndType(tenantId, AuthMethodType.SMS_OTP))
                .thenReturn(Optional.of(row(AuthMethodType.SMS_OTP, false)));

        assertThat(disabled.isLoginMethodAllowedForTenant(tenantId, AuthMethodType.SMS_OTP)).isTrue();
        assertThat(disabled.isLoginMethodExplicitlyDisabled(tenantId, AuthMethodType.SMS_OTP)).isFalse();
    }
}
