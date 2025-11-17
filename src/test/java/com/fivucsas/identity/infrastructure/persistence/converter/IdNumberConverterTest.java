package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.IdNumber;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for IdNumberConverter.
 * Tests bidirectional conversion between IdNumber value object and String.
 */
class IdNumberConverterTest {

    private IdNumberConverter converter;
    private static final String VALID_ID = "12345678910";

    @BeforeEach
    void setUp() {
        converter = new IdNumberConverter();
    }

    @Test
    void shouldConvertIdNumberToDatabaseColumn() {
        // Given
        IdNumber idNumber = IdNumber.of(VALID_ID);

        // When
        String dbValue = converter.convertToDatabaseColumn(idNumber);

        // Then
        assertEquals(VALID_ID, dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullIdNumberToDatabase() {
        // When
        String dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToIdNumber() {
        // Given
        String dbValue = VALID_ID;

        // When
        IdNumber idNumber = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(idNumber);
        assertEquals(VALID_ID, idNumber.getValue());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        IdNumber idNumber = converter.convertToEntityAttribute(null);

        // Then
        assertNull(idNumber);
    }

    @Test
    void shouldValidateChecksumWhenConvertingFromDatabase() {
        // Given - Valid Turkish ID with correct checksum
        String validId = "10000000146";

        // When
        IdNumber idNumber = converter.convertToEntityAttribute(validId);

        // Then
        assertNotNull(idNumber);
        assertEquals(validId, idNumber.getValue());
    }

    @Test
    void shouldRejectInvalidChecksumWhenConvertingFromDatabase() {
        // Given - Invalid checksum
        String invalidId = "12345678911";

        // When & Then
        assertThrows(IllegalArgumentException.class,
            () -> converter.convertToEntityAttribute(invalidId));
    }

    @Test
    void shouldBeReversible() {
        // Given
        String originalDbValue = VALID_ID;

        // When - Convert to entity then back to database
        IdNumber idNumber = converter.convertToEntityAttribute(originalDbValue);
        String dbValue = converter.convertToDatabaseColumn(idNumber);

        // Then
        assertEquals(originalDbValue, dbValue);
    }

    @Test
    void shouldTrimWhitespaceWhenConvertingFromDatabase() {
        // Given
        String dbValueWithSpaces = "  " + VALID_ID + "  ";

        // When
        IdNumber idNumber = converter.convertToEntityAttribute(dbValueWithSpaces);

        // Then
        assertEquals(VALID_ID, idNumber.getValue());
    }

    @Test
    void shouldPreserveIdNumberForMultipleValidIds() {
        // Given
        String id1 = "12345678910";
        String id2 = "10000000146";

        // When
        IdNumber idNumber1 = converter.convertToEntityAttribute(id1);
        IdNumber idNumber2 = converter.convertToEntityAttribute(id2);

        String dbValue1 = converter.convertToDatabaseColumn(idNumber1);
        String dbValue2 = converter.convertToDatabaseColumn(idNumber2);

        // Then
        assertEquals(id1, dbValue1);
        assertEquals(id2, dbValue2);
        assertNotEquals(idNumber1, idNumber2);
    }
}
