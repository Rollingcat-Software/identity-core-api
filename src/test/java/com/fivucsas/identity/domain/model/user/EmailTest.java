package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Email value object.
 * Tests validation, normalization, and behavior.
 */
class EmailTest {

    @Test
    void shouldCreateValidEmail() {
        // Given
        String validEmail = "user@example.com";

        // When
        Email email = Email.of(validEmail);

        // Then
        assertNotNull(email);
        assertEquals("user@example.com", email.getValue());
    }

    @Test
    void shouldNormalizeEmailToLowercase() {
        // Given
        String mixedCaseEmail = "User@EXAMPLE.COM";

        // When
        Email email = Email.of(mixedCaseEmail);

        // Then
        assertEquals("user@example.com", email.getValue());
    }

    @Test
    void shouldTrimWhitespace() {
        // Given
        String emailWithSpaces = "  user@example.com  ";

        // When
        Email email = Email.of(emailWithSpaces);

        // Then
        assertEquals("user@example.com", email.getValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void shouldRejectNullOrEmptyEmail(String invalidEmail) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> Email.of(invalidEmail)
        );
        assertEquals("Email cannot be null or empty", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "invalid",
        "invalid@",
        "@example.com",
        "user@",
        "user.example.com",
        "user @example.com",
        "user@exam ple.com",
        "user@@example.com",
        "user@example",
        "user@.com",
        "user@example..com"
    })
    void shouldRejectInvalidEmailFormats(String invalidEmail) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> Email.of(invalidEmail)
        );
        assertEquals("Invalid email format", exception.getMessage());
    }

    @Test
    void shouldRejectEmailExceedingMaxLength() {
        // Given - email with 256 characters
        String tooLongEmail = "a".repeat(245) + "@example.com";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> Email.of(tooLongEmail)
        );
        assertTrue(exception.getMessage().contains("Email cannot exceed 255 characters"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "user@example.com",
        "user.name@example.com",
        "user+tag@example.co.uk",
        "user_name@sub.example.com",
        "user123@example-domain.org",
        "a@b.co"
    })
    void shouldAcceptValidEmailFormats(String validEmail) {
        // When
        Email email = Email.of(validEmail);

        // Then
        assertNotNull(email);
        assertEquals(validEmail.toLowerCase(), email.getValue());
    }

    @Test
    void shouldExtractLocalPart() {
        // Given
        Email email = Email.of("username@example.com");

        // When
        String localPart = email.getLocalPart();

        // Then
        assertEquals("username", localPart);
    }

    @Test
    void shouldExtractDomain() {
        // Given
        Email email = Email.of("user@example.com");

        // When
        String domain = email.getDomain();

        // Then
        assertEquals("example.com", domain);
    }

    @Test
    void shouldBeEqualWhenValuesSame() {
        // Given
        Email email1 = Email.of("user@example.com");
        Email email2 = Email.of("user@example.com");

        // When & Then
        assertEquals(email1, email2);
        assertEquals(email1.hashCode(), email2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenValuesDifferent() {
        // Given
        Email email1 = Email.of("user1@example.com");
        Email email2 = Email.of("user2@example.com");

        // When & Then
        assertNotEquals(email1, email2);
    }

    @Test
    void shouldBeEqualRegardlessOfInputCase() {
        // Given
        Email email1 = Email.of("User@Example.COM");
        Email email2 = Email.of("user@example.com");

        // When & Then - Both normalized to lowercase
        assertEquals(email1, email2);
    }

    @Test
    void shouldReturnValueInToString() {
        // Given
        Email email = Email.of("user@example.com");

        // When
        String toString = email.toString();

        // Then
        assertEquals("user@example.com", toString);
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        Email email = Email.of("user@example.com");

        // When & Then
        assertEquals(email, email);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        Email email = Email.of("user@example.com");

        // When & Then
        assertNotEquals(null, email);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        Email email = Email.of("user@example.com");
        String string = "user@example.com";

        // When & Then
        assertNotEquals(email, string);
    }
}
