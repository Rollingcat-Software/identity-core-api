package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.Email;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for EmailConverter.
 * Tests bidirectional conversion between Email value object and String.
 */
class EmailConverterTest {

    private EmailConverter converter;

    @BeforeEach
    void setUp() {
        converter = new EmailConverter();
    }

    @Test
    void shouldConvertEmailToDatabaseColumn() {
        // Given
        Email email = Email.of("user@example.com");

        // When
        String dbValue = converter.convertToDatabaseColumn(email);

        // Then
        assertEquals("user@example.com", dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullEmailToDatabase() {
        // When
        String dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToEmail() {
        // Given
        String dbValue = "user@example.com";

        // When
        Email email = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(email);
        assertEquals("user@example.com", email.getValue());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        Email email = converter.convertToEntityAttribute(null);

        // Then
        assertNull(email);
    }

    @Test
    void shouldNormalizeEmailWhenConvertingFromDatabase() {
        // Given - Database has uppercase email
        String dbValue = "USER@EXAMPLE.COM";

        // When
        Email email = converter.convertToEntityAttribute(dbValue);

        // Then - Email value object normalizes to lowercase
        assertEquals("user@example.com", email.getValue());
    }

    @Test
    void shouldMaintainEmailCaseWhenStoringNormalizedEmail() {
        // Given - Email already normalized
        Email email = Email.of("User@Example.COM");

        // When
        String dbValue = converter.convertToDatabaseColumn(email);

        // Then - Should store normalized (lowercase) version
        assertEquals("user@example.com", dbValue);
    }

    @Test
    void shouldBeReversible() {
        // Given
        String originalDbValue = "user@example.com";

        // When - Convert to entity then back to database
        Email email = converter.convertToEntityAttribute(originalDbValue);
        String dbValue = converter.convertToDatabaseColumn(email);

        // Then
        assertEquals(originalDbValue, dbValue);
    }
}
