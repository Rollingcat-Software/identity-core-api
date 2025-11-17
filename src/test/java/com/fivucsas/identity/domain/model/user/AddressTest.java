package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Address value object.
 * Tests address validation and formatting.
 */
class AddressTest {

    @Test
    void shouldCreateValidAddress() {
        // Given
        String validAddress = "123 Main Street, Springfield, IL 62701";

        // When
        Address address = Address.of(validAddress);

        // Then
        assertNotNull(address);
        assertEquals(validAddress, address.getValue());
    }

    @Test
    void shouldTrimWhitespace() {
        // Given
        String addressWithSpaces = "  123 Main Street  ";

        // When
        Address address = Address.of(addressWithSpaces);

        // Then
        assertEquals("123 Main Street", address.getValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void shouldRejectNullOrEmptyAddress(String invalidAddress) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> Address.of(invalidAddress)
        );
        assertEquals("Address cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectAddressTooShort() {
        // Given - address with 4 characters (minimum is 5)
        String tooShortAddress = "1234";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> Address.of(tooShortAddress)
        );
        assertTrue(exception.getMessage().contains("Address must be at least 5 characters"));
    }

    @Test
    void shouldAcceptMinimumLengthAddress() {
        // Given - address with exactly 5 characters
        String minAddress = "12345";

        // When
        Address address = Address.of(minAddress);

        // Then
        assertNotNull(address);
        assertEquals(minAddress, address.getValue());
    }

    @Test
    void shouldRejectAddressExceedingMaxLength() {
        // Given - address with 501 characters
        String tooLongAddress = "a".repeat(501);

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> Address.of(tooLongAddress)
        );
        assertTrue(exception.getMessage().contains("Address cannot exceed 500 characters"));
    }

    @Test
    void shouldAcceptMaximumLengthAddress() {
        // Given - address with exactly 500 characters
        String maxAddress = "a".repeat(500);

        // When
        Address address = Address.of(maxAddress);

        // Then
        assertNotNull(address);
        assertEquals(500, address.getValue().length());
    }

    @Test
    void shouldReturnNullForOfNullableWithNull() {
        // When
        Address address = Address.ofNullable(null);

        // Then
        assertNull(address);
    }

    @Test
    void shouldReturnNullForOfNullableWithEmpty() {
        // When
        Address address = Address.ofNullable("");

        // Then
        assertNull(address);
    }

    @Test
    void shouldReturnNullForOfNullableWithWhitespace() {
        // When
        Address address = Address.ofNullable("   ");

        // Then
        assertNull(address);
    }

    @Test
    void shouldCreateAddressForOfNullableWithValidInput() {
        // Given
        String validAddress = "123 Main Street";

        // When
        Address address = Address.ofNullable(validAddress);

        // Then
        assertNotNull(address);
        assertEquals(validAddress, address.getValue());
    }

    @Test
    void shouldReturnShortFormForShortAddress() {
        // Given - address with less than 50 characters
        String shortAddress = "123 Main St";
        Address address = Address.of(shortAddress);

        // When
        String shortForm = address.getShortForm();

        // Then
        assertEquals(shortAddress, shortForm);
    }

    @Test
    void shouldReturnShortFormForLongAddress() {
        // Given - address with more than 50 characters
        String longAddress = "123 Very Long Street Name, Springfield, Illinois 62701, United States of America";
        Address address = Address.of(longAddress);

        // When
        String shortForm = address.getShortForm();

        // Then
        assertEquals(50, shortForm.length());
        assertTrue(shortForm.endsWith("..."));
        assertEquals("123 Very Long Street Name, Springfield, Ill...", shortForm);
    }

    @Test
    void shouldReturnShortFormForExactly50Characters() {
        // Given - address with exactly 50 characters
        String exactAddress = "a".repeat(50);
        Address address = Address.of(exactAddress);

        // When
        String shortForm = address.getShortForm();

        // Then
        assertEquals(exactAddress, shortForm);
        assertFalse(shortForm.endsWith("..."));
    }

    @Test
    void shouldBeEqualWhenValuesSame() {
        // Given
        Address address1 = Address.of("123 Main Street");
        Address address2 = Address.of("123 Main Street");

        // When & Then
        assertEquals(address1, address2);
        assertEquals(address1.hashCode(), address2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenValuesDifferent() {
        // Given
        Address address1 = Address.of("123 Main Street");
        Address address2 = Address.of("456 Oak Avenue");

        // When & Then
        assertNotEquals(address1, address2);
    }

    @Test
    void shouldReturnValueInToString() {
        // Given
        String addressValue = "123 Main Street";
        Address address = Address.of(addressValue);

        // When
        String toString = address.toString();

        // Then
        assertEquals(addressValue, toString);
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        Address address = Address.of("123 Main Street");

        // When & Then
        assertEquals(address, address);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        Address address = Address.of("123 Main Street");

        // When & Then
        assertNotEquals(null, address);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        Address address = Address.of("123 Main Street");
        String string = "123 Main Street";

        // When & Then
        assertNotEquals(address, string);
    }

    @Test
    void shouldHandleMultilineAddress() {
        // Given - address with newlines
        String multilineAddress = "123 Main Street\nApt 4B\nSpringfield, IL 62701";
        Address address = Address.of(multilineAddress);

        // When & Then
        assertEquals(multilineAddress, address.getValue());
    }

    @Test
    void shouldHandleInternationalAddress() {
        // Given - international address with special characters
        String internationalAddress = "Rue de la Paix 123, 75002 Paris, France";
        Address address = Address.of(internationalAddress);

        // When & Then
        assertEquals(internationalAddress, address.getValue());
    }
}
