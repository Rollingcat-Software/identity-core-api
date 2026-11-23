package com.fivucsas.identity.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.StepType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.AuthMethodRepository;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RateLimitService;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Regression test for identity-core-api #285: concurrent logins starved the Hikari
 * pool because a login held one pooled connection (its own transaction, plus the
 * request-bound EntityManager of open-in-view) while REQUIRES_NEW audit and
 * enrollment-health writes asked for a second one, and the biometric existence
 * probe (an HTTP call) ran while those connections were held.
 *
 * <p>The pool is shrunk to {@value #POOL_SIZE} connections and more logins than
 * that are fired at the same moment through the real HTTP stack. A login that needs
 * two connections at once deadlocks against its neighbours until Hikari's
 * connection timeout breaks the cycle, so the request fails. With the fix every
 * login needs at most one connection at a time and all of them succeed.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Login connection-pool starvation regression (#285)")
class LoginConnectionPoolIT {

    private static final int POOL_SIZE = 2;
    private static final int CONCURRENT_LOGINS = 3 * POOL_SIZE;
    private static final String PASSWORD = "Password123!";
    private static final String LOOPBACK_IP = "127.0.0.1";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_pool_test").withUsername("test").withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> String.valueOf(POOL_SIZE));
        registry.add("spring.datasource.hikari.minimum-idle", () -> String.valueOf(POOL_SIZE));
        // Long enough for queued logins to wait their turn behind BCrypt on a slow
        // runner; a deadlocked login still fails because nobody ever releases.
        registry.add("spring.datasource.hikari.connection-timeout", () -> "10000");
    }

    @LocalServerPort private int port;

    @Autowired private UserRepository userRepository;
    @Autowired private JpaTenantRepository tenantRepository;
    @Autowired private AuthFlowRepository authFlowRepository;
    @Autowired private AuthMethodRepository authMethodRepository;
    @Autowired private UserEnrollmentRepository userEnrollmentRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private RateLimitService rateLimitService;
    @Autowired private EntityManagerFactory entityManagerFactory;
    @Autowired private DataSource dataSource;
    @Autowired private ObjectMapper objectMapper;

    @MockitoBean private BiometricServicePort biometricServicePort;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void resetLoginRateLimit() {
        rateLimitService.resetRateLimit(LOOPBACK_IP, RateLimitService.RateLimitType.LOGIN);
    }

    @Test
    @DisplayName("execute_WhenMoreConcurrentPasswordLoginsThanPoolConnections_ShouldAllSucceed")
    void execute_WhenMoreConcurrentPasswordLoginsThanPoolConnections_ShouldAllSucceed() throws Exception {
        Tenant tenant = tenant("PoolPwd");
        List<String> emails = users(tenant, "pwd", CONCURRENT_LOGINS);

        List<HttpResponse<String>> responses = loginConcurrently(emails);

        assertThat(responses).allSatisfy(response -> {
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            assertThat(json(response).path("accessToken").asText()).isNotBlank();
        });
    }

    @Test
    @DisplayName("execute_WhenMoreConcurrentFaceFlowLoginsThanPoolConnections_ShouldAllReachMfaStep")
    void execute_WhenMoreConcurrentFaceFlowLoginsThanPoolConnections_ShouldAllReachMfaStep() throws Exception {
        when(biometricServicePort.faceEnrollmentExists(any(), anyString())).thenReturn(Boolean.TRUE);
        Tenant tenant = tenant("PoolFace");
        passwordThenFaceFlow(tenant);
        List<String> emails = users(tenant, "face", CONCURRENT_LOGINS);

        List<HttpResponse<String>> responses = loginConcurrently(emails);

        assertThat(responses).allSatisfy(response -> {
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            assertThat(json(response).path("mfaRequired").asBoolean()).isTrue();
        });
    }

    @Test
    @DisplayName("execute_WhenFaceEnrollmentIsProbed_ShouldHoldNoDatabaseConnectionDuringTheHttpCall")
    void execute_WhenFaceEnrollmentIsProbed_ShouldHoldNoDatabaseConnectionDuringTheHttpCall() throws Exception {
        List<String> heldDuringProbe = new CopyOnWriteArrayList<>();
        when(biometricServicePort.faceEnrollmentExists(any(), anyString())).thenAnswer(invocation -> {
            if (TransactionSynchronizationManager.isActualTransactionActive()) {
                heldDuringProbe.add("transaction");
            }
            if (TransactionSynchronizationManager.hasResource(entityManagerFactory)) {
                heldDuringProbe.add("entity manager");
            }
            if (TransactionSynchronizationManager.hasResource(dataSource)) {
                heldDuringProbe.add("jdbc connection");
            }
            return Boolean.TRUE;
        });
        Tenant tenant = tenant("ProbeFace");
        passwordThenFaceFlow(tenant);
        String email = users(tenant, "probe", 1).get(0);

        HttpResponse<String> response = login(email);

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(heldDuringProbe).as("resources bound to the login thread during the bio probe").isEmpty();
    }

    private List<HttpResponse<String>> loginConcurrently(List<String> emails) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(emails.size());
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<HttpResponse<String>>> futures = new ArrayList<>();
            for (String email : emails) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return login(email);
                }));
            }
            start.countDown();
            List<HttpResponse<String>> responses = new ArrayList<>();
            for (Future<HttpResponse<String>> future : futures) {
                responses.add(future.get(120, TimeUnit.SECONDS));
            }
            return responses;
        } finally {
            pool.shutdownNow();
        }
    }

    private HttpResponse<String> login(String email) throws Exception {
        String body = objectMapper.writeValueAsString(java.util.Map.of("email", email, "password", PASSWORD));
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://" + LOOPBACK_IP + ":" + port + "/api/v1/auth/login"))
                .timeout(Duration.ofSeconds(90))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode json(HttpResponse<String> response) {
        try {
            return objectMapper.readTree(response.body());
        } catch (Exception e) {
            throw new AssertionError("Login response is not JSON: " + response.body(), e);
        }
    }

    private Tenant tenant(String name) {
        return tenantRepository.save(Tenant.builder()
                .name(name + "-" + UUID.randomUUID())
                .slug(name.toLowerCase(java.util.Locale.ROOT) + "-" + UUID.randomUUID())
                .contactEmail("ops@" + name.toLowerCase(java.util.Locale.ROOT) + ".test")
                .status(TenantStatus.ACTIVE)
                .build());
    }

    private List<String> users(Tenant tenant, String prefix, int count) {
        String passwordHash = passwordEncoder.encode(PASSWORD);
        List<String> emails = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String email = prefix + "-" + i + "-" + UUID.randomUUID() + "@pool.test";
            User user = userRepository.save(User.builder()
                    .email(email).passwordHash(passwordHash)
                    .firstName("Pool").lastName("Login").status(UserStatus.ACTIVE).tenant(tenant).build());
            userEnrollmentRepository.save(UserEnrollment.builder()
                    .user(user).tenant(tenant)
                    .authMethodType(AuthMethodType.FACE)
                    .status(EnrollmentStatus.ENROLLED)
                    .build());
            emails.add(email);
        }
        return emails;
    }

    private void passwordThenFaceFlow(Tenant tenant) {
        AuthFlow flow = AuthFlow.builder().tenant(tenant).name("Login-" + UUID.randomUUID())
                .operationType(OperationType.APP_LOGIN).isDefault(true).isActive(true)
                .steps(new ArrayList<>()).build();
        int order = 1;
        for (AuthMethodType type : List.of(AuthMethodType.PASSWORD, AuthMethodType.FACE)) {
            AuthMethod method = authMethodRepository.findByType(type).orElseThrow();
            flow.getSteps().add(AuthFlowStep.builder().authFlow(flow).stepOrder(order++)
                    .authMethod(method).stepType(StepType.SEQUENTIAL).isRequired(true).build());
        }
        authFlowRepository.save(flow);
    }
}
