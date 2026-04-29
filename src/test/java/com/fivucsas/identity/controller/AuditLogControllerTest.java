package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.GetStatisticsUseCase;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.exception.GlobalExceptionHandler;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for AuditLogController focused on AUDIT_2026-04-28_EDGE.md
 * finding #4: {@code /api/v1/audit-logs?size=...} previously accepted
 * unbounded values, allowing a single request to allocate the whole
 * audit table. After the fix, {@code @Min(1) @Max(100)} on size +
 * {@code @Validated} on the controller class enforces the bound, and
 * GlobalExceptionHandler.handleConstraintViolation maps the violation
 * to a clean 400 instead of the default 500.
 */
@WebMvcTest(controllers = AuditLogController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@Import(GlobalExceptionHandler.class)
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("Audit Log Controller Tests")
class AuditLogControllerTest {

    @Autowired private MockMvc mockMvc;

    @MockBean private AuditLogRepository auditLogRepository;
    @MockBean private GetStatisticsUseCase getStatisticsUseCase;
    @MockBean private RbacAuthorizationService rbacService;
    @MockBean private TenantScopeResolver tenantScopeResolver;

    // Security + infra beans needed to start the WebMvc slice.
    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
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
    @DisplayName("GET /api/v1/audit-logs?size=10000000 - rejected with 400 (cap enforced)")
    void getAuditLogs_WhenSizeAboveMax_ShouldReturn400() throws Exception {
        // No need to stub repository — request must fail at parameter validation
        // before reaching the controller body.
        mockMvc.perform(get("/api/v1/audit-logs").param("size", "10000000"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Failed"));
    }

    @Test
    @DisplayName("GET /api/v1/audit-logs?size=0 - rejected with 400 (Min(1))")
    void getAuditLogs_WhenSizeZero_ShouldReturn400() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs").param("size", "0"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Failed"));
    }

    @Test
    @DisplayName("GET /api/v1/audit-logs?size=100 - allowed (boundary)")
    void getAuditLogs_WhenSizeAtMax_ShouldSucceed() throws Exception {
        Page<com.fivucsas.identity.entity.AuditLog> empty =
                new PageImpl<>(Collections.emptyList(), PageRequest.of(0, 100), 0);
        when(tenantScopeResolver.currentScope()).thenReturn(null);
        when(auditLogRepository.findAll(any(PageRequest.class))).thenReturn(empty);

        mockMvc.perform(get("/api/v1/audit-logs").param("size", "100"))
                .andExpect(status().isOk());
    }
}
