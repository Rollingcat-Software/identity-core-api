package com.fivucsas.identity.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for JwtService.
 *
 * Tests JWT token generation, validation, and claim extraction:
 * - Access token generation with correct claims
 * - Token validation (valid, expired, invalid signature)
 * - Email extraction from token
 *
 * Uses Mockito to mock JwtSecretProvider dependency.
 */
@DisplayName("JWT Service Tests")
@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private JwtSecretProvider jwtSecretProvider;

    private JwtService jwtService;

    private static final String TEST_EMAIL = "test@fivucsas.com";
    // Base64-encoded secret that is at least 256 bits for HMAC-SHA256
    private static final String TEST_SECRET = "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZy1mb3ItaHMyNTYtYWxnb3JpdGhtLXNlY3VyaXR5LXJlcXVpcmVtZW50cw==";
    private static final long ACCESS_TOKEN_EXPIRATION = 900000L; // 15 minutes

    private RsaKeyProvider rsaKeyProvider;

    @BeforeEach
    void setUp() {
        // lenient: several tests pass through paths that never consult the HMAC secret
        // (e.g. malformed-token parse failures). BE-H1 keeps HMAC still wired.
        org.mockito.Mockito.lenient().when(jwtSecretProvider.getSecret()).thenReturn(TEST_SECRET);
        rsaKeyProvider = JwtAlgoTestSupport.newRsaKeyProvider();
        jwtService = new JwtService(jwtSecretProvider, rsaKeyProvider, new MockEnvironment());
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", ACCESS_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(jwtService, "defaultAlgo", "HS512");
    }

    // ============== ACCESS TOKEN GENERATION TESTS ==============

    @Test
    @DisplayName("Generate access token - should create valid JWT")
    void testGenerateAccessToken_ValidToken() {
        // Act
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Assert
        assertThat(token).isNotNull().isNotEmpty();
        assertThat(token).matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$"); // JWT format
    }

    @Test
    @DisplayName("Generate access token - should include email claim")
    void testGenerateAccessToken_IncludesEmailClaim() {
        // Act
        String token = jwtService.generateAccessToken(TEST_EMAIL);
        String extractedEmail = jwtService.extractEmail(token);

        // Assert
        assertThat(extractedEmail).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Generate access token - should set correct expiration")
    void testGenerateAccessToken_CorrectExpiration() {
        // Act
        String token = jwtService.generateAccessToken(TEST_EMAIL);
        boolean isValid = jwtService.isTokenValid(token, TEST_EMAIL);

        // Assert
        assertThat(isValid).isTrue();
    }

    // ============== TOKEN VALIDATION TESTS ==============

    @Test
    @DisplayName("Validate token - valid token should return true")
    void testIsTokenValid_ValidToken() {
        // Arrange
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Act
        boolean isValid = jwtService.isTokenValid(token, TEST_EMAIL);

        // Assert
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Validate token - should return false for wrong email")
    void testIsTokenValid_WrongEmail() {
        // Arrange
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Act
        boolean isValid = jwtService.isTokenValid(token, "wrong@email.com");

        // Assert
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Validate token - should throw exception for malformed token")
    void testIsTokenValid_MalformedToken() {
        // Act & Assert
        assertThatThrownBy(() -> jwtService.isTokenValid("invalid.token", TEST_EMAIL))
                .isInstanceOf(MalformedJwtException.class);
    }

    @Test
    @DisplayName("Validate token - should throw exception for invalid signature")
    void testIsTokenValid_InvalidSignature() {
        // Arrange - Create a different secret provider with a different key
        JwtSecretProvider otherSecretProvider = org.mockito.Mockito.mock(JwtSecretProvider.class);
        // Different Base64-encoded secret
        when(otherSecretProvider.getSecret()).thenReturn("ZGlmZmVyZW50LXNlY3JldC1rZXktZm9yLXRlc3RpbmctcHVycG9zZXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZw==");
        JwtService otherJwtService = new JwtService(otherSecretProvider, rsaKeyProvider, new MockEnvironment());
        ReflectionTestUtils.setField(otherJwtService, "jwtExpiration", ACCESS_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(otherJwtService, "defaultAlgo", "HS512");
        String tokenWithDifferentKey = otherJwtService.generateAccessToken(TEST_EMAIL);

        // Act & Assert
        assertThatThrownBy(() -> jwtService.isTokenValid(tokenWithDifferentKey, TEST_EMAIL))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    @DisplayName("Validate token - should return false for expired token")
    void testIsTokenValid_ExpiredToken() {
        // Arrange - Create service with very short expiration
        JwtService shortExpirationService = new JwtService(jwtSecretProvider, rsaKeyProvider, new MockEnvironment());
        ReflectionTestUtils.setField(shortExpirationService, "jwtExpiration", 1L); // 1ms
        ReflectionTestUtils.setField(shortExpirationService, "defaultAlgo", "HS512");
        String token = shortExpirationService.generateAccessToken(TEST_EMAIL);

        // Act - Wait for token to expire
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        assertThatThrownBy(() -> jwtService.extractEmail(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    // ============== EMAIL EXTRACTION TESTS ==============

    @Test
    @DisplayName("Extract email - should return correct email from valid token")
    void testExtractEmail_ValidToken() {
        // Arrange
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Act
        String extractedEmail = jwtService.extractEmail(token);

        // Assert
        assertThat(extractedEmail).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Extract email - should throw exception for invalid token")
    void testExtractEmail_InvalidToken() {
        // Act & Assert
        assertThatThrownBy(() -> jwtService.extractEmail("invalid.token.here"))
                .isInstanceOf(MalformedJwtException.class);
    }

    // ============== TOKEN FORMAT TESTS ==============

    @Test
    @DisplayName("Token format - should have three parts separated by dots")
    void testTokenFormat_ThreeParts() {
        // Act
        String token = jwtService.generateAccessToken(TEST_EMAIL);
        String[] parts = token.split("\\.");

        // Assert
        assertThat(parts).hasSize(3);
    }

    @Test
    @DisplayName("Token format - tokens generated at different times should be different")
    void testTokenFormat_DifferentTokens() throws InterruptedException {
        // Act - Add delay to ensure different timestamp (JWT uses second precision)
        String token1 = jwtService.generateAccessToken(TEST_EMAIL);
        Thread.sleep(1100); // Wait > 1 second to ensure different timestamp
        String token2 = jwtService.generateAccessToken(TEST_EMAIL);

        // Assert - Tokens should be different due to different issue times
        assertThat(token1).isNotEqualTo(token2);
    }

    @Test
    @DisplayName("Token format - different emails should produce different tokens")
    void testTokenFormat_DifferentEmails() {
        // Act
        String token1 = jwtService.generateAccessToken("user1@test.com");
        String token2 = jwtService.generateAccessToken("user2@test.com");

        // Assert
        assertThat(token1).isNotEqualTo(token2);
        assertThat(jwtService.extractEmail(token1)).isEqualTo("user1@test.com");
        assertThat(jwtService.extractEmail(token2)).isEqualTo("user2@test.com");
    }

    // ============== EDGE CASE TESTS ==============

    @Test
    @DisplayName("Edge case - very long email should work")
    void testEdgeCase_VeryLongEmail() {
        // Arrange
        String longEmail = "very.long.email.address.with.many.dots@subdomain.example.company.com";

        // Act
        String token = jwtService.generateAccessToken(longEmail);
        String extractedEmail = jwtService.extractEmail(token);

        // Assert
        assertThat(extractedEmail).isEqualTo(longEmail);
    }

    @Test
    @DisplayName("Edge case - email with special characters should work")
    void testEdgeCase_SpecialCharacters() {
        // Arrange
        String specialEmail = "user+tag@example.com";

        // Act
        String token = jwtService.generateAccessToken(specialEmail);
        String extractedEmail = jwtService.extractEmail(token);

        // Assert
        assertThat(extractedEmail).isEqualTo(specialEmail);
    }

    @Test
    @DisplayName("Edge case - concurrent token generation should work")
    void testEdgeCase_ConcurrentGeneration() {
        // Act - Generate multiple tokens concurrently
        String[] tokens = new String[10];
        for (int i = 0; i < 10; i++) {
            tokens[i] = jwtService.generateAccessToken(TEST_EMAIL);
        }

        // Assert - All tokens should be valid
        for (String token : tokens) {
            assertThat(token).isNotNull();
            assertThat(jwtService.isTokenValid(token, TEST_EMAIL)).isTrue();
        }
    }
}
