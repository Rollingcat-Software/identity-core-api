package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.input.UserDataExportUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers GDPR Art. 20 / KVKK export endpoint.
 *
 * <p>Scenarios:
 * <ul>
 *   <li>self-export succeeds (200 + attachment header)</li>
 *   <li>tenant-admin exports a user in their tenant</li>
 *   <li>user A attempting to export user B returns 403</li>
 *   <li>unknown user id returns 404 (via UserNotFoundException)</li>
 *   <li>response excludes sensitive fields (sanity check on payload structure)</li>
 * </ul>
 */
@WebMvcTest(controllers = UserDataExportController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("User Data Export Controller Tests (GDPR Art. 20 / KVKK)")
class UserDataExportControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private UserDataExportUseCase userDataExportUseCase;
    @MockBean private RbacAuthorizationService rbacService;
    @MockBean private RateLimitService rateLimitService;
    @MockBean private AuditLogPort auditLogPort;

    // Security / infra beans required by the test slice
    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;
    @MockBean private OtpService otpService;
    @MockBean private EmailService emailService;
    @MockBean private SmsService smsService;

    private UUID userAId;
    private UUID userBId;
    private Tenant tenantA;
    private User userA;
    private User userB;
    private User tenantAdmin;

    @BeforeEach
    void setUp() {
        userAId = UUID.randomUUID();
        userBId = UUID.randomUUID();
        tenantA = Tenant.builder()
            .id(UUID.randomUUID())
            .name("Tenant A")
            .slug("tenant-a")
            .build();

        userA = User.builder()
            .id(userAId)
            .email("alice@example.com")
            .passwordHash("$2a$10$hash")
            .firstName("Alice")
            .lastName("A")
            .status(UserStatus.ACTIVE)
            .userType(UserType.TENANT_MEMBER)
            .tenant(tenantA)
            .build();

        userB = User.builder()
            .id(userBId)
            .email("bob@example.com")
            .passwordHash("$2a$10$hash")
            .firstName("Bob")
            .lastName("B")
            .status(UserStatus.ACTIVE)
            .userType(UserType.TENANT_MEMBER)
            .tenant(tenantA)
            .build();

        tenantAdmin = User.builder()
            .id(UUID.randomUUID())
            .email("admin@example.com")
            .passwordHash("$2a$10$hash")
            .firstName("Admin")
            .lastName("A")
            .status(UserStatus.ACTIVE)
            .userType(UserType.TENANT_ADMIN)
            .tenant(tenantA)
            .build();

        when(rateLimitService.allowDataExport(anyString())).thenReturn(true);
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - self-export returns 200 + attachment header")
    void selfExport_succeeds() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(userA));

        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("exportedAt", "2026-04-16T00:00:00Z");
        bundle.put("exportFormatVersion", "1.0");
        Map<String, Object> userSection = new LinkedHashMap<>();
        userSection.put("id", userAId.toString());
        userSection.put("email", "alice@example.com");
        bundle.put("user", userSection);
        when(userDataExportUseCase.exportUserData(userAId)).thenReturn(bundle);

        mockMvc.perform(get("/api/v1/users/" + userAId + "/export"))
            .andExpect(status().isOk())
            .andExpect(header().string("Content-Disposition",
                org.hamcrest.Matchers.containsString("attachment")))
            .andExpect(header().string("Content-Disposition",
                org.hamcrest.Matchers.containsString("fivucsas-export-" + userAId)))
            .andExpect(content().contentType("application/json"))
            .andExpect(jsonPath("$.exportFormatVersion").value("1.0"))
            .andExpect(jsonPath("$.user.id").value(userAId.toString()));

        verify(auditLogPort).logSecurityEvent(
            eq(userAId.toString()),
            eq("USER_DATA_EXPORTED"),
            any(),
            any());
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - tenant admin exports tenant user")
    void tenantAdmin_canExport_tenantMember() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantAdmin));
        when(rbacService.canManageUser(userBId)).thenReturn(true);

        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("exportFormatVersion", "1.0");
        when(userDataExportUseCase.exportUserData(userBId)).thenReturn(bundle);

        mockMvc.perform(get("/api/v1/users/" + userBId + "/export"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.exportFormatVersion").value("1.0"));

        verify(auditLogPort).logSecurityEvent(
            eq(tenantAdmin.getId().toString()),
            eq("USER_DATA_EXPORTED"),
            any(),
            any());
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - user A cannot export user B (403)")
    void userA_cannotExport_userB() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(userA));

        mockMvc.perform(get("/api/v1/users/" + userBId + "/export"))
            .andExpect(status().isForbidden());

        verify(userDataExportUseCase, never()).exportUserData(any());
        verify(auditLogPort, never()).logSecurityEvent(anyString(), eq("USER_DATA_EXPORTED"), any(), any());
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - unknown user returns 404")
    void unknownUser_returns404() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantAdmin));
        when(rbacService.canManageUser(any())).thenReturn(true);
        UUID unknownId = UUID.randomUUID();
        doThrow(new UserNotFoundException(unknownId.toString()))
            .when(userDataExportUseCase).exportUserData(unknownId);

        mockMvc.perform(get("/api/v1/users/" + unknownId + "/export"))
            .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - bundle excludes sensitive fields by contract")
    void exportBundle_excludesSensitiveFields() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(userA));

        // Simulate the service's real shape — it should never surface these keys.
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("exportFormatVersion", "1.0");
        Map<String, Object> userSection = new LinkedHashMap<>();
        userSection.put("id", userAId.toString());
        userSection.put("email", "alice@example.com");
        // NO passwordHash, NO twoFactorSecret, NO backupCodes, NO embedding
        bundle.put("user", userSection);
        bundle.put("biometricEnrollments", java.util.List.of(
            Map.of("id", UUID.randomUUID().toString(), "method", "FACE", "enrolledAt", "2026-01-01T00:00:00Z")
        ));
        when(userDataExportUseCase.exportUserData(userAId)).thenReturn(bundle);

        mockMvc.perform(get("/api/v1/users/" + userAId + "/export"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.passwordHash").doesNotExist())
            .andExpect(jsonPath("$.user.twoFactorSecret").doesNotExist())
            .andExpect(jsonPath("$.user.twoFactorBackupCodes").doesNotExist())
            .andExpect(jsonPath("$.user.emailVerificationToken").doesNotExist())
            .andExpect(jsonPath("$.user.passwordResetToken").doesNotExist())
            .andExpect(jsonPath("$.biometricEnrollments[0].embedding").doesNotExist());
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - no current user returns 403 (GlobalExceptionHandler maps UnauthorizedException to 403)")
    void unauthenticated_returns403() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/users/" + userAId + "/export"))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /api/v1/users/{id}/export - rate limit exceeded returns 429")
    void rateLimitExceeded_returns429() throws Exception {
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(userA));
        when(rateLimitService.allowDataExport(userAId.toString())).thenReturn(false);
        when(rateLimitService.getSecondsUntilRefill(anyString(),
                eq(RateLimitService.RateLimitType.EXPORT))).thenReturn(3600L);

        mockMvc.perform(get("/api/v1/users/" + userAId + "/export"))
            .andExpect(status().isTooManyRequests());

        verify(userDataExportUseCase, never()).exportUserData(any());
    }
}
