package com.fivucsas.identity.integration;

import com.fivucsas.identity.application.service.OAuth2Service;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.OAuth2ClientRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end guard for the production defect of 2026-11-03/09: the refresh token minted by
 * the {@code authorization_code} exchange was never written, so every later
 * {@code refresh_token} grant failed with {@code invalid_grant}.
 *
 * <p>Real PostgreSQL (Testcontainers) and real Redis (the CI service / local container on
 * localhost:6379, as for the other {@code *IntegrationTest} classes). The test method is
 * deliberately NOT {@code @Transactional}: a test-managed transaction would hold the
 * entity in its persistence context and hide a missing flush, which is the bug.</p>
 */
@SpringBootTest
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("OAuth2 code exchange persists a refresh token a later refresh grant can use")
class OAuth2RefreshTokenPersistenceIntegrationTest {

    private static final String REDIRECT_URI = "fivucsas://callback";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_test").withUsername("test").withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    @Autowired private OAuth2Service oAuth2Service;
    @Autowired private JpaTenantRepository tenantRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private OAuth2ClientRepository clientRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JdbcTemplate jdbcTemplate;

    @Test
    @DisplayName("exchangeCode then refreshAccessToken with the returned refresh_token succeeds")
    void exchangeCode_WhenThenRefreshedWithReturnedToken_ShouldPersistAndRotate() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Tenant tenant = tenantRepository.save(Tenant.builder()
                .name("Oauth" + suffix).slug("oauth-" + suffix)
                .contactEmail("ops@oauth" + suffix + ".test")
                .status(TenantStatus.ACTIVE).build());
        User user = userRepository.save(User.builder()
                .email("mobile-" + suffix + "@oauth.test")
                .passwordHash(passwordEncoder.encode("Password123!"))
                .firstName("Mobile").lastName("User").status(UserStatus.ACTIVE)
                .tenant(tenant).build());
        String clientId = "mobile-" + suffix;
        clientRepository.save(OAuth2Client.builder()
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(UUID.randomUUID().toString()))
                .clientName("Mobile " + suffix)
                .redirectUris("[\"" + REDIRECT_URI + "\"]")
                .allowedScopes("openid profile email")
                .confidential(false)
                .tenant(tenant)
                .build());

        String verifier = "verifier-" + UUID.randomUUID() + "-" + UUID.randomUUID();
        String code = oAuth2Service.generateAuthorizationCode(
                user.getEmail(), clientId, REDIRECT_URI, "openid profile email",
                null, s256(verifier), "S256");

        Map<String, Object> issued = oAuth2Service.exchangeCode(
                code, clientId, REDIRECT_URI, null, verifier, "127.0.0.1", "it-agent");

        String refreshToken = (String) issued.get("refresh_token");
        assertThat(refreshToken).isNotBlank();
        Integer rows = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM refresh_tokens WHERE user_id = ?", Integer.class, user.getId());
        assertThat(rows).isEqualTo(1);

        Map<String, Object> refreshed = oAuth2Service.refreshAccessToken(
                refreshToken, clientId, "127.0.0.1", "it-agent");

        assertThat(refreshed.get("access_token")).isNotNull();
        assertThat((String) refreshed.get("refresh_token")).isNotBlank().isNotEqualTo(refreshToken);
    }

    private static String s256(String verifier) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
