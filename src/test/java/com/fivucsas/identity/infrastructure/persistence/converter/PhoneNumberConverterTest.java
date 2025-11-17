package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.PhoneNumber;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PhoneNumberConverter.
 * Tests bidirectional conversion between PhoneNumber value object and String.
 */
class PhoneNumberConverterTest {

    private PhoneNumberConverter converter;

    @BeforeEach
    void setUp() {
        converter = new PhoneNumberConverter();
    }

    @Test
    void shouldConvertPhoneNumberToDatabaseColumn() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+905551234567");

        // When
        String dbValue = converter.convertToDatabaseColumn(phone);

        // Then
        assertEquals("+905551234567", dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullPhoneToDatabase() {
        // When
        String dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToPhoneNumber() {
        // Given
        String dbValue = "+905551234567";

        // When
        PhoneNumber phone = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(phone);
        assertEquals("+905551234567", phone.getValue());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        PhoneNumber phone = converter.convertToEntityAttribute(null);

        // Then
        assertNull(phone);
    }

    @Test
    void shouldHandleInternationalPhoneNumbers() {
        // Given
        PhoneNumber usPhone = PhoneNumber.of("+12025551234");
        PhoneNumber ukPhone = PhoneNumber.of("+442071234567");

        // When
        String usDbValue = converter.convertToDatabaseColumn(usPhone);
        String ukDbValue = converter.convertToDatabaseColumn(ukPhone);

        // Then
        assertEquals("+12025551234", usDbValue);
        assertEquals("+442071234567", ukDbValue);
    }

    @Test
    void shouldBeReversible() {
        // Given
        String originalDbValue = "+905551234567";

        // When - Convert to entity then back to database
        PhoneNumber phone = converter.convertToEntityAttribute(originalDbValue);
        String dbValue = converter.convertToDatabaseColumn(phone);

        // Then
        assertEquals(originalDbValue, dbValue);
    }

    @Test
    void shouldTrimWhitespaceWhenConvertingFromDatabase() {
        // Given
        String dbValueWithSpaces = "  +905551234567  ";

        // When
        PhoneNumber phone = converter.convertToEntityAttribute(dbValueWithSpaces);

        // Then
        assertEquals("+905551234567", phone.getValue());
    }
}
