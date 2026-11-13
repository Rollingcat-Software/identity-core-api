package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.EnrollmentHealthService;
import com.fivucsas.identity.application.service.EnrollmentQueryService;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.exception.GlobalExceptionHandler;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.RbacPermissionEvaluator;
import com.fivucsas.identity.security.TenantScopeResolver;
import com.fivucsas.identity.security.UserSecurityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The user-scoped enrollment endpoints ({@code /api/v1/users/{userId}/enrollments...})
 * with the REAL method-security wiring (RBAC evaluator + {@code @rbac}).
 *
 * <p>They are guarded by {@code hasPermission(#userId, 'User', ...)}. A TENANT_ADMIN
 * holds every tenant-scoped permission implicitly, so unless the evaluator checks
 * that the target user belongs to the caller's tenant, an admin of tenant A reads
 * and writes the enrollments of a tenant-B user by id (AX-5 cross-tenant run,
 * identity-core-api 2a0d087).</p>
 */
@SpringJUnitConfig(UserEnrollmentTenantGuardSecurityTest.Config.class)
@DisplayName("User-scoped enrollment endpoints: target user must be in the caller's tenant")
class UserEnrollmentTenantGuardSecurityTest {

    static final UUID TENANT_A = UUID.fromString("0a0a0a0a-0000-4000-8000-00000000000a");
    static final UUID TENANT_B = UUID.fromString("0b0b0b0b-0000-4000-8000-00000000000b");
    static final UUID USER_IN_A = UUID.fromString("1a1a1a1a-0000-4000-8000-00000000001a");
    static final UUID USER_IN_B = UUID.fromString("1b1b1b1b-0000-4000-8000-00000000001b");

    // @TestConfiguration keeps this nested config out of component scanning of the
    // @SpringBootTest contexts (see TenantAuthMethodSecurityTest for the history).
    @TestConfiguration
    @EnableMethodSecurity
    static class Config {
        @Bean UserRepository userRepository() { return mock(UserRepository.class); }
        @Bean RoleRepository roleRepository() { return mock(RoleRepository.class); }
        @Bean ManageEnrollmentUseCase manageEnrollmentUseCase() { return mock(ManageEnrollmentUseCase.class); }
        @Bean EnrollmentHealthService enrollmentHealthService() { return mock(EnrollmentHealthService.class); }

        @Bean
        @SuppressWarnings("unchecked")
        TenantFilterBypass tenantFilterBypass() {
            TenantFilterBypass bypass = mock(TenantFilterBypass.class);
            when(bypass.runWithoutTenantFilter(any())).thenAnswer(inv -> ((Supplier<Object>) inv.getArgument(0)).get());
            return bypass;
        }

        @Bean(name = "rbac")
        RbacAuthorizationService rbac(UserRepository users, RoleRepository roles, TenantFilterBypass bypass) {
            return new RbacAuthorizationService(users, roles, bypass);
        }

        @Bean(name = "userSecurityService")
        UserSecurityService userSecurityService(UserRepository users) {
            return new UserSecurityService(users);
        }

        @Bean
        MethodSecurityExpressionHandler methodSecurityExpressionHandler(RbacAuthorizationService rbac) {
            DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
            handler.setPermissionEvaluator(new RbacPermissionEvaluator(rbac));
            return handler;
        }

        @Bean
        EnrollmentController enrollmentController(ManageEnrollmentUseCase useCase,
                                                  EnrollmentHealthService health,
                                                  RbacAuthorizationService rbac) {
            return new EnrollmentController(
                    mock(EnrollmentQueryService.class),
                    mock(UserEnrollmentRepository.class),
                    useCase,
                    mock(EnrollBiometricUseCase.class),
                    mock(BiometricServicePort.class),
                    rbac,
                    health,
                    mock(TenantScopeResolver.class));
        }
    }

    @Autowired EnrollmentController controller;
    @Autowired UserRepository userRepository;
    @Autowired ManageEnrollmentUseCase useCase;
    @Autowired EnrollmentHealthService healthService;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        Mockito.reset(userRepository, useCase, healthService);
        when(useCase.getUserEnrollments(any())).thenReturn(List.of());
        when(healthService.validateEnrollments(any())).thenReturn(Map.of());
        when(userRepository.findById(USER_IN_A)).thenReturn(Optional.of(user(USER_IN_A, "member-a@example.test",
                UserType.TENANT_MEMBER, TENANT_A)));
        when(userRepository.findById(USER_IN_B)).thenReturn(Optional.of(user(USER_IN_B, "member-b@example.test",
                UserType.TENANT_MEMBER, TENANT_B)));
        mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static User user(UUID id, String email, UserType type, UUID tenantId) {
        return User.builder()
                .id(id)
                .email(email)
                .userType(type)
                .tenant(tenantId == null ? null : Tenant.builder().id(tenantId).name("t").build())
                .build();
    }

    private void signedInAs(String email, UserType type, UUID tenantId) {
        User caller = user(UUID.randomUUID(), email, type, tenantId);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(caller));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(email, "n/a", List.of()));
    }

    private void signedInAsTenantAdminOfA() {
        signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);
    }

    @Nested
    @DisplayName("GET /api/v1/users/{userId}/enrollments")
    class ListUserEnrollments {

        @Test
        void getUserEnrollments_WhenAdminOfAnotherTenant_ShouldReturn403AndNotReadAnything() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(get("/api/v1/users/{id}/enrollments", USER_IN_B))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).getUserEnrollments(any());
        }

        @Test
        void getUserEnrollments_WhenAdminOfSameTenant_ShouldReturn200() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(get("/api/v1/users/{id}/enrollments", USER_IN_A))
                    .andExpect(status().isOk());
        }

        @Test
        void getUserEnrollments_WhenRoot_ShouldReturn200ForAnyTenant() throws Exception {
            signedInAs("root@example.test", UserType.ROOT, null);

            mvc.perform(get("/api/v1/users/{id}/enrollments", USER_IN_B))
                    .andExpect(status().isOk());
        }

        @Test
        void getUserEnrollments_WhenTargetUserUnknown_ShouldReturn403() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(get("/api/v1/users/{id}/enrollments", UUID.randomUUID()))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).getUserEnrollments(any());
        }
    }

    @Nested
    @DisplayName("GET /api/v1/users/{userId}/enrollments/health")
    class EnrollmentHealth {

        @Test
        void getEnrollmentHealth_WhenAdminOfAnotherTenant_ShouldReturn403() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(get("/api/v1/users/{id}/enrollments/health", USER_IN_B))
                    .andExpect(status().isForbidden());
            verifyNoInteractions(healthService);
        }

        @Test
        void getEnrollmentHealth_WhenAdminOfSameTenant_ShouldReturn200() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(get("/api/v1/users/{id}/enrollments/health", USER_IN_A))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("POST /api/v1/users/{userId}/enrollments")
    class StartEnrollment {

        @Test
        void startEnrollment_WhenAdminOfAnotherTenant_ShouldReturn403AndWriteNothing() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/users/{id}/enrollments", USER_IN_B)
                            .param("tenantId", TENANT_B.toString())
                            .param("methodType", "FACE"))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).startEnrollment(any(), any(), any());
        }

        @Test
        void startEnrollment_WhenAdminOfSameTenant_ShouldReturn201() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/users/{id}/enrollments", USER_IN_A)
                            .param("tenantId", TENANT_A.toString())
                            .param("methodType", "FACE"))
                    .andExpect(status().isCreated());
        }

        @Test
        void startEnrollment_WhenAdminOfSameTenantPassesForeignTenantId_ShouldReturn403AndWriteNothing()
                throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/users/{id}/enrollments", USER_IN_A)
                            .param("tenantId", TENANT_B.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).startEnrollment(any(), any(), any());
        }

        @Test
        void startEnrollment_WhenSelfPassesForeignTenantId_ShouldReturn403AndWriteNothing() throws Exception {
            User self = user(USER_IN_A, "member-a@example.test", UserType.TENANT_MEMBER, TENANT_A);
            when(userRepository.findByEmail("member-a@example.test")).thenReturn(Optional.of(self));
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("member-a@example.test", "n/a", List.of()));

            mvc.perform(post("/api/v1/users/{id}/enrollments", USER_IN_A)
                            .param("tenantId", TENANT_B.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).startEnrollment(any(), any(), any());
        }

        @Test
        void startEnrollment_WhenSelfPassesOwnTenantId_ShouldReturn201() throws Exception {
            User self = user(USER_IN_A, "member-a@example.test", UserType.TENANT_MEMBER, TENANT_A);
            when(userRepository.findByEmail("member-a@example.test")).thenReturn(Optional.of(self));
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("member-a@example.test", "n/a", List.of()));

            mvc.perform(post("/api/v1/users/{id}/enrollments", USER_IN_A)
                            .param("tenantId", TENANT_A.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isCreated());
        }

        @Test
        void startEnrollment_WhenTenantIdOmitted_ShouldReachUseCaseWithNullTenant() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/users/{id}/enrollments", USER_IN_A)
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isCreated());
            verify(useCase).startEnrollment(USER_IN_A, null,
                    com.fivucsas.identity.domain.model.auth.AuthMethodType.EMAIL_OTP);
        }
    }

    @Nested
    @DisplayName("PUT /api/v1/users/{userId}/enrollments/{methodType}/complete")
    class CompleteEnrollment {

        @Test
        void completeEnrollment_WhenAdminOfAnotherTenant_ShouldReturn403AndWriteNothing() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(put("/api/v1/users/{id}/enrollments/FACE/complete", USER_IN_B))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).completeEnrollment(any(), any(), anyString());
        }

        @Test
        void completeEnrollment_WhenAdminOfSameTenant_ShouldReturn200() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(put("/api/v1/users/{id}/enrollments/FACE/complete", USER_IN_A))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("DELETE /api/v1/users/{userId}/enrollments/{methodType}")
    class RevokeEnrollment {

        @Test
        void revokeEnrollment_WhenAdminOfAnotherTenant_ShouldReturn403AndWriteNothing() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/users/{id}/enrollments/FACE", USER_IN_B))
                    .andExpect(status().isForbidden());
            verify(useCase, never()).revokeEnrollment(any(), any());
        }

        @Test
        void revokeEnrollment_WhenAdminOfSameTenant_ShouldReturn204() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/users/{id}/enrollments/FACE", USER_IN_A))
                    .andExpect(status().isNoContent());
        }
    }
}
