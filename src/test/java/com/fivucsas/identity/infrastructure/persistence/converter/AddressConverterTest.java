package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.Address;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AddressConverter.
 * Tests bidirectional conversion between Address value object and String.
 */
class AddressConverterTest {

    private AddressConverter converter;

    @BeforeEach
    void setUp() {
        converter = new AddressConverter();
    }

    @Test
    void shouldConvertAddressToDatabaseColumn() {
        // Given
        Address address = Address.of("123 Main Street, Springfield, IL 62701");

        // When
        String dbValue = converter.convertToDatabaseColumn(address);

        // Then
        assertEquals("123 Main Street, Springfield, IL 62701", dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullAddressToDatabase() {
        // When
        String dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToAddress() {
        // Given
        String dbValue = "123 Main Street, Springfield, IL 62701";

        // When
        Address address = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(address);
        assertEquals("123 Main Street, Springfield, IL 62701", address.getValue());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        Address address = converter.convertToEntityAttribute(null);

        // Then
        assertNull(address);
    }

    @Test
    void shouldHandleMultilineAddress() {
        // Given
        String multilineAddress = "123 Main Street\nApt 4B\nSpringfield, IL 62701";
        Address address = Address.of(multilineAddress);

        // When
        String dbValue = converter.convertToDatabaseColumn(address);

        // Then
        assertEquals(multilineAddress, dbValue);
    }

    @Test
    void shouldBeReversible() {
        // Given
        String originalDbValue = "123 Main Street, Springfield, IL 62701";

        // When - Convert to entity then back to database
        Address address = converter.convertToEntityAttribute(originalDbValue);
        String dbValue = converter.convertToDatabaseColumn(address);

        // Then
        assertEquals(originalDbValue, dbValue);
    }

    @Test
    void shouldTrimWhitespaceWhenConvertingFromDatabase() {
        // Given
        String dbValueWithSpaces = "  123 Main Street  ";

        // When
        Address address = converter.convertToEntityAttribute(dbValueWithSpaces);

        // Then
        assertEquals("123 Main Street", address.getValue());
    }

    @Test
    void shouldHandleLongAddresses() {
        // Given - Address close to max length (500 chars)
        String longAddress = "A".repeat(490) + ", USA";
        Address address = Address.of(longAddress);

        // When
        String dbValue = converter.convertToDatabaseColumn(address);
        Address roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals(longAddress, dbValue);
        assertEquals(address, roundTrip);
    }
}
