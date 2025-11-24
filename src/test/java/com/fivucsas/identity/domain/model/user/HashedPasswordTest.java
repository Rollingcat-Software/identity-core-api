package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HashedPassword value object.
 * Tests BCrypt hash validation and security.
 */
class HashedPasswordTest {

    // Valid BCrypt hash (for "password123")
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Test
    void shouldCreateValidHashedPassword() {
        // When
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // Then
        assertNotNull(password);
        assertEquals(VALID_BCRYPT_HASH, password.getValue());
    }

    @Test
    void shouldRejectNullHash() {
        // When & Then
        NullPointerException exception = assertThrows(
            NullPointerException.class,
            () -> HashedPassword.of(null)
        );
        assertEquals("Hashed password cannot be null", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    void shouldRejectEmptyHash(String emptyHash) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> HashedPassword.of(emptyHash)
        );
        assertEquals("Hashed password cannot be empty", exception.getMessage());
    }

    @Test
    void shouldRejectHashWithIncorrectLength() {
        // Given - BCrypt hashes must be exactly 60 characters
        String tooShortHash = "$2a$10$N9qo8uLOickgx2ZMRZoMye";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> HashedPassword.of(tooShortHash)
        );
        assertEquals("Invalid BCrypt hash format", exception.getMessage());
    }

    @Test
    void shouldRejectHashWithInvalidPrefix() {
        // Given - BCrypt hashes must start with $2
        String invalidHash = "$3a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> HashedPassword.of(invalidHash)
        );
        assertEquals("Invalid BCrypt hash format", exception.getMessage());
    }

    @Test
    void shouldRejectPlainTextPassword() {
        // Given - Plain text password (not a BCrypt hash)
        String plainText = "password123";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> HashedPassword.of(plainText)
        );
        assertEquals("Invalid BCrypt hash format", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    })
    void shouldAcceptValidBCryptVariants(String validHash) {
        // When
        HashedPassword password = HashedPassword.of(validHash);

        // Then
        assertNotNull(password);
        assertEquals(validHash, password.getValue());
    }

    @Test
    void shouldNeverExposeHashInToString() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When
        String toString = password.toString();

        // Then
        assertEquals("[PROTECTED]", toString);
        assertFalse(toString.contains(VALID_BCRYPT_HASH));
    }

    @Test
    void shouldBeEqualWhenHashesSame() {
        // Given
        HashedPassword password1 = HashedPassword.of(VALID_BCRYPT_HASH);
        HashedPassword password2 = HashedPassword.of(VALID_BCRYPT_HASH);

        // When & Then
        assertEquals(password1, password2);
        assertEquals(password1.hashCode(), password2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenHashesDifferent() {
        // Given
        String hash1 = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
        String hash2 = "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12";

        HashedPassword password1 = HashedPassword.of(hash1);
        HashedPassword password2 = HashedPassword.of(hash2);

        // When & Then
        assertNotEquals(password1, password2);
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When & Then
        assertEquals(password, password);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When & Then
        assertNotEquals(null, password);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When & Then
        assertNotEquals(password, VALID_BCRYPT_HASH);
    }

    @Test
    void shouldPreventHashModification() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When - Attempt to get reference
        String hash = password.getValue();

        // Then - Original should remain unchanged (String is immutable)
        assertEquals(VALID_BCRYPT_HASH, password.getValue());
        assertEquals(hash, password.getValue());
    }
}
