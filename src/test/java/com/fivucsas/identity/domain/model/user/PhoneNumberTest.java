package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PhoneNumber value object.
 * Tests international format validation.
 */
class PhoneNumberTest {

    @Test
    void shouldCreateValidPhoneNumber() {
        // Given
        String validPhone = "+905551234567";

        // When
        PhoneNumber phone = PhoneNumber.of(validPhone);

        // Then
        assertNotNull(phone);
        assertEquals("+905551234567", phone.getValue());
    }

    @Test
    void shouldTrimWhitespace() {
        // Given
        String phoneWithSpaces = "  +905551234567  ";

        // When
        PhoneNumber phone = PhoneNumber.of(phoneWithSpaces);

        // Then
        assertEquals("+905551234567", phone.getValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void shouldRejectNullOrEmptyPhone(String invalidPhone) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> PhoneNumber.of(invalidPhone)
        );
        assertEquals("Phone number cannot be null or empty", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "5551234567",                // Missing +
        "+0551234567",               // Starts with 0 (invalid country code)
        "+905512345",                // Too short (only 9 digits after +)
        "+9055123456789012345",      // Too long (18 digits, way over limit)
        "+90 555 123 4567",          // Contains spaces
        "+90-555-123-4567",          // Contains dashes
        "+ABC1234567890"             // Contains letters
    })
    void shouldRejectInvalidPhoneFormats(String invalidPhone) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> PhoneNumber.of(invalidPhone)
        );
        assertTrue(exception.getMessage().contains("Invalid phone number format"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "+905551234567",        // Turkey (11 digits)
        "+12025551234",         // USA (11 digits)
        "+442071234567",        // UK (12 digits)
        "+4915123456789",       // Germany (13 digits)
        "+33123456789",         // France (11 digits)
        "+861234567890",        // China (12 digits)
        "+81312345678",         // Japan (11 digits)
        "+61234567890",         // Australia (11 digits)
        "+551234567890"         // Brazil (12 digits)
    })
    void shouldAcceptValidInternationalPhoneNumbers(String validPhone) {
        // When
        PhoneNumber phone = PhoneNumber.of(validPhone);

        // Then
        assertNotNull(phone);
        assertEquals(validPhone, phone.getValue());
    }

    @Test
    void shouldExtractCountryCodeForUSA() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+12025551234");

        // When
        String countryCode = phone.getCountryCode();

        // Then
        assertEquals("1", countryCode);
    }

    @Test
    void shouldExtractCountryCodeForTurkey() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+905551234567");

        // When
        String countryCode = phone.getCountryCode();

        // Then
        assertEquals("90", countryCode);
    }

    @Test
    void shouldExtractCountryCodeForUK() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+442071234567");

        // When
        String countryCode = phone.getCountryCode();

        // Then
        assertEquals("44", countryCode);
    }

    @Test
    void shouldExtractCountryCodeForGermany() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+4915123456789");

        // When
        String countryCode = phone.getCountryCode();

        // Then
        assertEquals("49", countryCode);
    }

    @Test
    void shouldReturnNullForOfNullableWithNull() {
        // When
        PhoneNumber phone = PhoneNumber.ofNullable(null);

        // Then
        assertNull(phone);
    }

    @Test
    void shouldReturnNullForOfNullableWithEmpty() {
        // When
        PhoneNumber phone = PhoneNumber.ofNullable("");

        // Then
        assertNull(phone);
    }

    @Test
    void shouldReturnNullForOfNullableWithWhitespace() {
        // When
        PhoneNumber phone = PhoneNumber.ofNullable("   ");

        // Then
        assertNull(phone);
    }

    @Test
    void shouldCreatePhoneForOfNullableWithValidInput() {
        // Given
        String validPhone = "+905551234567";

        // When
        PhoneNumber phone = PhoneNumber.ofNullable(validPhone);

        // Then
        assertNotNull(phone);
        assertEquals(validPhone, phone.getValue());
    }

    @Test
    void shouldBeEqualWhenValuesSame() {
        // Given
        PhoneNumber phone1 = PhoneNumber.of("+905551234567");
        PhoneNumber phone2 = PhoneNumber.of("+905551234567");

        // When & Then
        assertEquals(phone1, phone2);
        assertEquals(phone1.hashCode(), phone2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenValuesDifferent() {
        // Given
        PhoneNumber phone1 = PhoneNumber.of("+905551234567");
        PhoneNumber phone2 = PhoneNumber.of("+905559876543");

        // When & Then
        assertNotEquals(phone1, phone2);
    }

    @Test
    void shouldReturnValueInToString() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+905551234567");

        // When
        String toString = phone.toString();

        // Then
        assertEquals("+905551234567", toString);
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+905551234567");

        // When & Then
        assertEquals(phone, phone);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+905551234567");

        // When & Then
        assertNotEquals(null, phone);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        PhoneNumber phone = PhoneNumber.of("+905551234567");
        String string = "+905551234567";

        // When & Then
        assertNotEquals(phone, string);
    }
}
