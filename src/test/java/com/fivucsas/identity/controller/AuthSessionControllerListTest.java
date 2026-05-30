package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ExecuteAuthSessionUseCase;
import com.fivucsas.identity.application.port.input.GetActiveSessionsUseCase;
import com.fivucsas.identity.application.port.input.RevokeAllSessionsUseCase;
import com.fivucsas.identity.application.port.input.RevokeSessionUseCase;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.service.AuthSessionQueryService;
import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Controller-layer tests for the admin {@code GET /api/v1/auth/sessions}
 * endpoint added by feat/auth-sessions-admin-list.
 *
 * <p>Security filters are disabled — these tests target the
 * <i>tenant-scope coercion logic</i> in the controller (which sits AFTER
 * authn/authz), not Spring Security itself. The {@code @PreAuthorize}
 * gate is exercised by the existing integration coverage on similar
 * {@code @rbac.isTenantAdmin()} endpoints.</p>
 */
@WebMvcTest(controllers = AuthSessionController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("AuthSessionController — admin list endpoint")
class AuthSessionControllerListTest {

    @Autowired private MockMvc mockMvc;

    @MockBean private ExecuteAuthSessionUseCase executeAuthSessionUseCase;
    @MockBean private GetActiveSessionsUseCase getActiveSessionsUseCase;
    @MockBean private RevokeSessionUseCase revokeSessionUseCase;
    @MockBean private RevokeAllSessionsUseCase revokeAllSessionsUseCase;
    @MockBean private AuthSessionQueryService authSessionQueryService;
    @MockBean private TenantScopeResolver tenantScopeResolver;

    // Security / infrastructure beans (required by Spring context even though
    // filters are disabled — these match the pattern in EnrollmentControllerTest).
    @MockBean private RbacAuthorizationService rbacService;
    @MockBean private TenantRepository tenantRepository;
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;
    @MockBean private OtpService otpService;
    @MockBean private EmailService emailService;
    @MockBean private SmsService smsService;

    @Test
    @DisplayName("TENANT_ADMIN: caller scope wins, even when caller lies about tenantId")
    void tenantAdminScopeIsCoerced() throws Exception {
        UUID callerTenant = UUID.randomUUID();
        UUID otherTenant = UUID.randomUUID();
        when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
        when(authSessionQueryService.listForTenant(any(), any(), any(), eq(0), eq(20)))
                .thenReturn(Map.of("content", List.of(), "totalElements", 0L,
                        "totalPages", 0, "page", 0, "size", 20));

        mockMvc.perform(get("/api/v1/auth/sessions").param("tenantId", otherTenant.toString()))
                .andExpect(status().isOk());

        ArgumentCaptor<UUID> tenantCaptor = ArgumentCaptor.forClass(UUID.class);
        verify(authSessionQueryService).listForTenant(
                tenantCaptor.capture(), any(), any(), eq(0), eq(20));
        // Caller-supplied tenantId was IGNORED; resolver scope used instead.
        org.assertj.core.api.Assertions.assertThat(tenantCaptor.getValue()).isEqualTo(callerTenant);
    }

    @Test
    @DisplayName("ROOT: caller-supplied tenantId honored when scope is null")
    void superAdminUsesProvidedTenantId() throws Exception {
        UUID requested = UUID.randomUUID();
        when(tenantScopeResolver.currentScope()).thenReturn(null);
        when(authSessionQueryService.listForTenant(eq(requested), any(), any(), eq(0), eq(20)))
                .thenReturn(Map.of("content", List.of(), "totalElements", 0L,
                        "totalPages", 0, "page", 0, "size", 20));

        mockMvc.perform(get("/api/v1/auth/sessions").param("tenantId", requested.toString()))
                .andExpect(status().isOk());

        verify(authSessionQueryService).listForTenant(
                eq(requested), any(), any(), eq(0), eq(20));
    }

    @Test
    @DisplayName("ROOT without tenantId param → platform-wide listing (null tenantId passed through)")
    void superAdminWithoutTenantIdIsPlatformWide() throws Exception {
        when(tenantScopeResolver.currentScope()).thenReturn(null);
        when(authSessionQueryService.listForTenant(eq((UUID) null), any(), any(), eq(0), eq(20)))
                .thenReturn(Map.of("content", List.of(), "totalElements", 0L,
                        "totalPages", 0, "page", 0, "size", 20));

        mockMvc.perform(get("/api/v1/auth/sessions"))
                .andExpect(status().isOk());

        verify(authSessionQueryService).listForTenant(
                eq((UUID) null), any(), any(), eq(0), eq(20));
    }

    @Test
    @DisplayName("Caller without resolvable tenant → empty page (fail closed)")
    void unresolvableTenantReturnsEmpty() throws Exception {
        when(tenantScopeResolver.currentScope()).thenReturn(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE);

        mockMvc.perform(get("/api/v1/auth/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(0))
                .andExpect(jsonPath("$.totalElements").value(0));

        verify(authSessionQueryService, never()).listForTenant(any(), any(), any(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    @DisplayName("status=IN_PROGRESS,CREATED → parsed into List<AuthSessionStatus>")
    void statusFilterParsed() throws Exception {
        UUID callerTenant = UUID.randomUUID();
        when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
        when(authSessionQueryService.listForTenant(any(), any(), any(), eq(0), eq(20)))
                .thenReturn(Map.of("content", List.of(), "totalElements", 0L,
                        "totalPages", 0, "page", 0, "size", 20));

        mockMvc.perform(get("/api/v1/auth/sessions").param("status", "IN_PROGRESS,CREATED"))
                .andExpect(status().isOk());

        @SuppressWarnings({"unchecked", "rawtypes"})
        ArgumentCaptor<List<AuthSessionStatus>> captor = (ArgumentCaptor) ArgumentCaptor.forClass(List.class);
        verify(authSessionQueryService).listForTenant(
                eq(callerTenant), captor.capture(), any(), eq(0), eq(20));
        org.assertj.core.api.Assertions.assertThat(captor.getValue())
                .containsExactly(AuthSessionStatus.IN_PROGRESS, AuthSessionStatus.CREATED);
    }

    @Test
    @DisplayName("Unknown status value → 400")
    void unknownStatusIs400() throws Exception {
        UUID callerTenant = UUID.randomUUID();
        when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);

        mockMvc.perform(get("/api/v1/auth/sessions").param("status", "FROZEN"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("status param empty → null/empty filter, no filter applied")
    void emptyStatusYieldsNoFilter() throws Exception {
        UUID callerTenant = UUID.randomUUID();
        when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
        when(authSessionQueryService.listForTenant(any(), any(), any(), eq(0), eq(20)))
                .thenReturn(Map.of("content", List.of(), "totalElements", 0L,
                        "totalPages", 0, "page", 0, "size", 20));

        mockMvc.perform(get("/api/v1/auth/sessions"))
                .andExpect(status().isOk());

        @SuppressWarnings({"unchecked", "rawtypes"})
        ArgumentCaptor<List<AuthSessionStatus>> captor = (ArgumentCaptor) ArgumentCaptor.forClass(List.class);
        verify(authSessionQueryService).listForTenant(
                eq(callerTenant), captor.capture(), any(), eq(0), eq(20));
        org.assertj.core.api.Assertions.assertThat(captor.getValue()).isEmpty();
    }
}
