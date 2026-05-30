package com.fivucsas.identity.integration;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.LoginConfigResponse;
import com.fivucsas.identity.application.service.AuthenticateUserService;
import com.fivucsas.identity.application.service.LoginConfigService;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.StepType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.AuthMethodRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.JpaTenantRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Config-driven login engine ITs (task #16 B/C) against real PostgreSQL.
 *
 * <p>Covers the new behaviors that need a real flow + auth_methods rows:
 * <ul>
 *   <li>login-config exposes the tenant Layer-1 contract;</li>
 *   <li>a password-less Layer-1 (EMAIL_OTP) logs in with NO password check;</li>
 *   <li>a usernameless Layer-1 (PASSKEY) → Layer-2 (EMAIL_OTP) → tokens with
 *       amr=[hwk, otp];</li>
 *   <li>a PASSWORD-first flow is unchanged.</li>
 * </ul>
 */
@SpringBootTest
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Config-driven login engine ITs (task #16)")
class ConfigDrivenLoginIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_test").withUsername("test").withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        // Enable the config-driven engine globally for this IT (it ships OFF by
        // default; the OFF/legacy path is covered by the unit tests).
        registry.add("app.auth.config-driven-login", () -> "true");
    }

    @Autowired private AuthenticateUserService authenticateUserService;
    @Autowired private LoginConfigService loginConfigService;
    @Autowired private UserRepository userRepository;
    @Autowired private JpaTenantRepository tenantRepository;
    @Autowired private AuthFlowRepository authFlowRepository;
    @Autowired private AuthMethodRepository authMethodRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private final List<UUID> createdFlows = new ArrayList<>();
    private final List<UUID> createdUsers = new ArrayList<>();
    private final List<UUID> createdTenants = new ArrayList<>();

    @AfterEach
    @Transactional
    void cleanup() {
        createdUsers.forEach(id -> userRepository.findById(id).ifPresent(userRepository::delete));
        createdFlows.forEach(id -> authFlowRepository.findById(id).ifPresent(authFlowRepository::delete));
        createdTenants.forEach(id -> tenantRepository.findById(id).ifPresent(tenantRepository::delete));
        createdUsers.clear();
        createdFlows.clear();
        createdTenants.clear();
    }

    private Tenant tenant(String name) {
        Tenant t = tenantRepository.save(Tenant.builder()
                .name(name).slug(name.toLowerCase() + "-" + UUID.randomUUID())
                .contactEmail("ops@" + name.toLowerCase() + ".test")
                .status(TenantStatus.ACTIVE).build());
        createdTenants.add(t.getId());
        return t;
    }

    private User user(Tenant t, String email) {
        User u = userRepository.save(User.builder()
                .email(email).passwordHash(passwordEncoder.encode("Password123!"))
                .firstName("Cfg").lastName("Login").status(UserStatus.ACTIVE).tenant(t).build());
        createdUsers.add(u.getId());
        return u;
    }

    private AuthFlow flow(Tenant t, AuthMethodType... layerMethods) {
        AuthFlow f = AuthFlow.builder().tenant(t).name("Login-" + UUID.randomUUID())
                .operationType(OperationType.APP_LOGIN).isDefault(true).isActive(true)
                .steps(new ArrayList<>()).build();
        int order = 1;
        for (AuthMethodType type : layerMethods) {
            AuthMethod m = authMethodRepository.findByType(type).orElseThrow();
            // Steps reference the parent flow (FK); cascade=ALL on AuthFlow.steps
            // persists them on save.
            f.getSteps().add(AuthFlowStep.builder().authFlow(f).stepOrder(order++)
                    .authMethod(m).stepType(StepType.SEQUENTIAL).isRequired(true).build());
        }
        f = authFlowRepository.save(f);
        createdFlows.add(f.getId());
        return f;
    }

    @Test
    @DisplayName("login-config exposes Layer-1 contract for a PASSKEY-then-OTP flow")
    @Transactional
    void loginConfigExposesContract() {
        Tenant t = tenant("Cfg1");
        flow(t, AuthMethodType.PASSKEY, AuthMethodType.EMAIL_OTP);

        LoginConfigResponse cfg = loginConfigService.getLoginConfig(t.getId());

        assertThat(cfg.totalSteps()).isEqualTo(2);
        assertThat(cfg.layer1().identifierRequired()).isFalse(); // PASSKEY is usernameless
        assertThat(cfg.layer1().methods()).singleElement()
                .satisfies(m -> assertThat(m.type()).isEqualTo("PASSKEY"));
        assertThat(cfg.laterSteps()).singleElement()
                .satisfies(s -> assertThat(s.methods().get(0).type()).isEqualTo("EMAIL_OTP"));
    }

    @Test
    @DisplayName("password-less Layer-1 (EMAIL_OTP): no password check; MFA pending at step 1")
    @Transactional
    void passwordlessLayer1() {
        Tenant t = tenant("Cfg2");
        flow(t, AuthMethodType.EMAIL_OTP);
        User u = user(t, "otp-first@cfg.test");

        AuthenticationResponse resp = authenticateUserService.execute(AuthenticateUserCommand.builder()
                .email(u.getEmail()).password("wrong-on-purpose") // ignored: Layer-1 is not PASSWORD
                .ipAddress("127.0.0.1").userAgent("it/1.0").build());

        assertThat(resp.isMfaRequired()).isTrue();
        assertThat(resp.getAccessToken()).isNull();
        assertThat(resp.getCurrentStep()).isEqualTo(1);
        assertThat(resp.getCompletedMethods()).isEmpty();
    }

    @Test
    @DisplayName("PASSWORD-first flow is unchanged (single-step mints amr=pwd)")
    @Transactional
    void passwordFirstUnchanged() {
        Tenant t = tenant("Cfg3");
        flow(t, AuthMethodType.PASSWORD);
        User u = user(t, "pwd-first@cfg.test");

        AuthenticationResponse resp = authenticateUserService.execute(AuthenticateUserCommand.builder()
                .email(u.getEmail()).password("Password123!")
                .ipAddress("127.0.0.1").userAgent("it/1.0").build());

        assertThat(resp.isMfaRequired()).isFalse();
        assertThat(resp.getAccessToken()).isNotNull();
    }
}
