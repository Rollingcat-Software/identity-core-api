package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.FullName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for FullNameConverter.
 * Tests bidirectional conversion between FullName value object and String.
 * FullName is stored as "firstName|lastName" in database.
 */
class FullNameConverterTest {

    private FullNameConverter converter;

    @BeforeEach
    void setUp() {
        converter = new FullNameConverter();
    }

    @Test
    void shouldConvertFullNameToDatabaseColumn() {
        // Given
        FullName fullName = FullName.of("John", "Doe");

        // When
        String dbValue = converter.convertToDatabaseColumn(fullName);

        // Then
        assertEquals("John|Doe", dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullFullNameToDatabase() {
        // When
        String dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToFullName() {
        // Given
        String dbValue = "John|Doe";

        // When
        FullName fullName = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(fullName);
        assertEquals("John", fullName.getFirstName());
        assertEquals("Doe", fullName.getLastName());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        FullName fullName = converter.convertToEntityAttribute(null);

        // Then
        assertNull(fullName);
    }

    @Test
    void shouldHandleNamesWithSpaces() {
        // Given
        FullName fullName = FullName.of("Mary Jane", "van der Berg");

        // When
        String dbValue = converter.convertToDatabaseColumn(fullName);
        FullName roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals("Mary Jane|van der Berg", dbValue);
        assertEquals(fullName, roundTrip);
    }

    @Test
    void shouldHandleNamesWithHyphens() {
        // Given
        FullName fullName = FullName.of("Mary-Jane", "Smith-Johnson");

        // When
        String dbValue = converter.convertToDatabaseColumn(fullName);
        FullName roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals("Mary-Jane|Smith-Johnson", dbValue);
        assertEquals(fullName, roundTrip);
    }

    @Test
    void shouldHandleNamesWithApostrophes() {
        // Given
        FullName fullName = FullName.of("O'Brien", "D'Angelo");

        // When
        String dbValue = converter.convertToDatabaseColumn(fullName);
        FullName roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals("O'Brien|D'Angelo", dbValue);
        assertEquals(fullName, roundTrip);
    }

    @Test
    void shouldBeReversible() {
        // Given
        String originalDbValue = "John|Doe";

        // When - Convert to entity then back to database
        FullName fullName = converter.convertToEntityAttribute(originalDbValue);
        String dbValue = converter.convertToDatabaseColumn(fullName);

        // Then
        assertEquals(originalDbValue, dbValue);
    }

    @Test
    void shouldHandleInternationalCharacters() {
        // Given
        FullName fullName = FullName.of("José", "Müller");

        // When
        String dbValue = converter.convertToDatabaseColumn(fullName);
        FullName roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals("José|Müller", dbValue);
        assertEquals(fullName, roundTrip);
    }

    @Test
    void shouldPreserveNameCase() {
        // Given
        FullName fullName = FullName.of("JOHN", "doe");

        // When
        String dbValue = converter.convertToDatabaseColumn(fullName);
        FullName roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals("JOHN|doe", dbValue);
        assertEquals("JOHN", roundTrip.getFirstName());
        assertEquals("doe", roundTrip.getLastName());
    }

    @Test
    void shouldReturnNullForEmptyDatabaseValue() {
        // When
        FullName fullName = converter.convertToEntityAttribute("");

        // Then
        assertNull(fullName);
    }

    @Test
    void shouldThrowExceptionForMalformedDatabaseValueWithoutPipe() {
        // Given - No pipe separator
        String malformedValue = "JohnDoe";

        // When & Then
        IllegalStateException exception = assertThrows(
            IllegalStateException.class,
            () -> converter.convertToEntityAttribute(malformedValue)
        );
        assertTrue(exception.getMessage().contains("Invalid FullName format in database"));
    }

    @Test
    void shouldHandleDatabaseValueWithMultiplePipes() {
        // Given - Multiple pipe separators result in invalid lastName containing pipe
        String dbValue = "John|Middle|Doe";

        // When/Then - Should throw exception because pipe is not valid in names
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> converter.convertToEntityAttribute(dbValue)
        );
        assertTrue(exception.getMessage().contains("invalid characters"));
    }
}
