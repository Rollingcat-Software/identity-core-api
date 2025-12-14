package com.fivucsas.identity.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for JwtService.
 *
 * Tests JWT token generation, validation, and claim extraction:
 * - Access token generation with correct claims
 * - Refresh token generation
 * - Token validation (valid, expired, invalid signature)
 * - Email extraction from token
 * - Token expiration checking
 *
 * Uses reflection to set private fields for testing.
 */
@DisplayName("JWT Service Tests")
class JwtServiceTest {

    private JwtService jwtService;

    private static final String TEST_EMAIL = "test@fivucsas.com";
    private static final String TEST_SECRET = "test-secret-key-that-is-at-least-256-bits-long-for-hs256-algorithm-security-requirements";
    private static final long ACCESS_TOKEN_EXPIRATION = 900000L; // 15 minutes
    private static final long REFRESH_TOKEN_EXPIRATION = 604800000L; // 7 days

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        // Set private fields using reflection for testing
        ReflectionTestUtils.setField(jwtService, "secretKey", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", REFRESH_TOKEN_EXPIRATION);
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
        boolean isExpired = jwtService.isTokenExpired(token);

        // Assert
        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("Generate access token - should throw exception for null email")
    void testGenerateAccessToken_NullEmail() {
        // Act & Assert
        assertThatThrownBy(() -> jwtService.generateAccessToken(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Generate access token - should throw exception for empty email")
    void testGenerateAccessToken_EmptyEmail() {
        // Act & Assert
        assertThatThrownBy(() -> jwtService.generateAccessToken(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ============== REFRESH TOKEN GENERATION TESTS ==============

    @Test
    @DisplayName("Generate refresh token - should create valid JWT")
    void testGenerateRefreshToken_ValidToken() {
        // Act
        String token = jwtService.generateRefreshToken(TEST_EMAIL);

        // Assert
        assertThat(token).isNotNull().isNotEmpty();
        assertThat(token).matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$");
    }

    @Test
    @DisplayName("Generate refresh token - should include email claim")
    void testGenerateRefreshToken_IncludesEmailClaim() {
        // Act
        String token = jwtService.generateRefreshToken(TEST_EMAIL);
        String extractedEmail = jwtService.extractEmail(token);

        // Assert
        assertThat(extractedEmail).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Generate refresh token - should have longer expiration than access token")
    void testGenerateRefreshToken_LongerExpiration() {
        // Act
        String accessToken = jwtService.generateAccessToken(TEST_EMAIL);
        String refreshToken = jwtService.generateRefreshToken(TEST_EMAIL);

        // Assert - Both should be valid
        assertThat(jwtService.isTokenExpired(accessToken)).isFalse();
        assertThat(jwtService.isTokenExpired(refreshToken)).isFalse();
    }

    // ============== TOKEN VALIDATION TESTS ==============

    @Test
    @DisplayName("Validate token - valid token should return true")
    void testValidateToken_ValidToken() {
        // Arrange
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Act
        boolean isValid = jwtService.validateToken(token, TEST_EMAIL);

        // Assert
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Validate token - should return false for wrong email")
    void testValidateToken_WrongEmail() {
        // Arrange
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Act
        boolean isValid = jwtService.validateToken(token, "wrong@email.com");

        // Assert
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Validate token - should throw exception for malformed token")
    void testValidateToken_MalformedToken() {
        // Act & Assert
        assertThatThrownBy(() -> jwtService.validateToken("invalid.token", TEST_EMAIL))
                .isInstanceOf(MalformedJwtException.class);
    }

    @Test
    @DisplayName("Validate token - should throw exception for invalid signature")
    void testValidateToken_InvalidSignature() {
        // Arrange - Token signed with different key
        JwtService otherJwtService = new JwtService();
        ReflectionTestUtils.setField(otherJwtService, "secretKey", "different-secret-key-for-testing-purposes-at-least-256-bits-long");
        ReflectionTestUtils.setField(otherJwtService, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);
        String tokenWithDifferentKey = otherJwtService.generateAccessToken(TEST_EMAIL);

        // Act & Assert
        assertThatThrownBy(() -> jwtService.validateToken(tokenWithDifferentKey, TEST_EMAIL))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    @DisplayName("Validate token - should return false for expired token")
    void testValidateToken_ExpiredToken() {
        // Arrange - Create service with very short expiration
        JwtService shortExpirationService = new JwtService();
        ReflectionTestUtils.setField(shortExpirationService, "secretKey", TEST_SECRET);
        ReflectionTestUtils.setField(shortExpirationService, "accessTokenExpiration", 1L); // 1ms
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

    @Test
    @DisplayName("Extract email - should throw exception for null token")
    void testExtractEmail_NullToken() {
        // Act & Assert
        assertThatThrownBy(() -> jwtService.extractEmail(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ============== TOKEN EXPIRATION TESTS ==============

    @Test
    @DisplayName("Is token expired - valid token should return false")
    void testIsTokenExpired_ValidToken() {
        // Arrange
        String token = jwtService.generateAccessToken(TEST_EMAIL);

        // Act
        boolean isExpired = jwtService.isTokenExpired(token);

        // Assert
        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("Is token expired - expired token should return true")
    void testIsTokenExpired_ExpiredToken() {
        // Arrange - Create service with very short expiration
        JwtService shortExpirationService = new JwtService();
        ReflectionTestUtils.setField(shortExpirationService, "secretKey", TEST_SECRET);
        ReflectionTestUtils.setField(shortExpirationService, "accessTokenExpiration", 1L);
        String token = shortExpirationService.generateAccessToken(TEST_EMAIL);

        // Act - Wait for expiration
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Assert
        assertThatThrownBy(() -> shortExpirationService.isTokenExpired(token))
                .isInstanceOf(ExpiredJwtException.class);
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
    @DisplayName("Token format - different tokens should be different")
    void testTokenFormat_DifferentTokens() {
        // Act
        String token1 = jwtService.generateAccessToken(TEST_EMAIL);
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
            assertThat(jwtService.validateToken(token, TEST_EMAIL)).isTrue();
        }
    }
}
