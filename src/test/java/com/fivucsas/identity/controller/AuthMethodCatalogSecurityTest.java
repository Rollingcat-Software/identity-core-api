package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ManageAuthMethodUseCase;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.exception.GlobalExceptionHandler;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.RbacPermissionEvaluator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Behavioural check of {@code GET /api/v1/tenants/{tenantId}/auth-methods/catalog}
 * with the REAL method-security wiring (RBAC evaluator + {@code @rbac}), not a
 * reflective annotation check: the catalog reveals whether a tenant is on the
 * PUZZLE canary list, so only that tenant's admins (and ROOT) may read it.
 */
@SpringJUnitConfig(AuthMethodCatalogSecurityTest.Config.class)
@DisplayName("Tenant auth-method catalog: tenant ownership enforced")
class AuthMethodCatalogSecurityTest {

    static final UUID TENANT_A = UUID.fromString("21069c39-ddad-495e-9e7b-da6a1e2f86fb");
    static final UUID TENANT_B = UUID.fromString("11111111-1111-1111-1111-111111111111");

    // @TestConfiguration (not @Configuration): excluded from component scanning,
    // so @SpringBootTest integration tests never pick up this second "rbac"
    // bean and expression handler next to SecurityConfig.
    @TestConfiguration
    @EnableMethodSecurity
    static class Config {
        @Bean UserRepository userRepository() { return mock(UserRepository.class); }
        @Bean RoleRepository roleRepository() { return mock(RoleRepository.class); }
        @Bean ManageAuthMethodUseCase manageAuthMethodUseCase() { return mock(ManageAuthMethodUseCase.class); }

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

        @Bean
        MethodSecurityExpressionHandler methodSecurityExpressionHandler(RbacAuthorizationService rbac) {
            DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
            handler.setPermissionEvaluator(new RbacPermissionEvaluator(rbac));
            return handler;
        }

        @Bean
        AuthMethodController authMethodController(ManageAuthMethodUseCase useCase) {
            return new AuthMethodController(useCase);
        }
    }

    @Autowired AuthMethodController controller;
    @Autowired UserRepository userRepository;
    @Autowired ManageAuthMethodUseCase useCase;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        Mockito.reset(userRepository, useCase);
        when(useCase.listCatalogForTenant(any())).thenReturn(List.of());
        mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void signedInAs(String email, UserType type, UUID tenantId) {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .userType(type)
                .tenant(tenantId == null ? null : Tenant.builder().id(tenantId).name("t").build())
                .build();
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(email, "n/a", List.of()));
    }

    @Test
    void adminOfTheTenant_gets200() throws Exception {
        signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        mvc.perform(get("/api/v1/tenants/{id}/auth-methods/catalog", TENANT_A))
                .andExpect(status().isOk());
    }

    @Test
    void adminOfAnotherTenant_gets403() throws Exception {
        signedInAs("admin-b@example.test", UserType.TENANT_ADMIN, TENANT_B);

        mvc.perform(get("/api/v1/tenants/{id}/auth-methods/catalog", TENANT_A))
                .andExpect(status().isForbidden());
    }

    @Test
    void memberWithoutThePermission_gets403_evenInTheirOwnTenant() throws Exception {
        signedInAs("member-a@example.test", UserType.TENANT_MEMBER, TENANT_A);

        mvc.perform(get("/api/v1/tenants/{id}/auth-methods/catalog", TENANT_A))
                .andExpect(status().isForbidden());
    }

    @Test
    void root_gets200_forAnyTenant() throws Exception {
        signedInAs("root@example.test", UserType.ROOT, null);

        mvc.perform(get("/api/v1/tenants/{id}/auth-methods/catalog", TENANT_A))
                .andExpect(status().isOk());
    }
}
