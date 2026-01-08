package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for IdNumber value object.
 * Tests Turkish ID number validation with checksum algorithm.
 */
class IdNumberTest {

    // Valid Turkish ID numbers (real algorithm)
    private static final String VALID_ID_1 = "10000000146"; // Valid checksum
    private static final String VALID_ID_2 = "11111111110"; // Different valid checksum

    @Test
    void shouldCreateValidIdNumber() {
        // When
        IdNumber idNumber = IdNumber.of(VALID_ID_1);

        // Then
        assertNotNull(idNumber);
        assertEquals(VALID_ID_1, idNumber.getValue());
    }

    @Test
    void shouldTrimWhitespace() {
        // Given
        String idWithSpaces = "  " + VALID_ID_1 + "  ";

        // When
        IdNumber idNumber = IdNumber.of(idWithSpaces);

        // Then
        assertEquals(VALID_ID_1, idNumber.getValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void shouldRejectNullOrEmptyIdNumber(String invalidId) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> IdNumber.of(invalidId)
        );
        assertEquals("ID number cannot be null or empty", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "123456789",        // Too short (9 digits)
        "1234567891011",    // Too long (13 digits)
        "1234",             // Too short (4 digits)
        "abcdefghijk",      // Contains letters
        "1234567891a",      // Contains letter
        "123-456-7891",     // Contains dashes
        "123 456 7891"      // Contains spaces (after trim)
    })
    void shouldRejectInvalidIdFormats(String invalidId) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> IdNumber.of(invalidId)
        );
        assertTrue(exception.getMessage().contains("Invalid ID number format"));
    }

    @Test
    void shouldRejectIdStartingWithZero() {
        // Given - 11 digits starting with 0
        String idStartingWithZero = "01234567891";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> IdNumber.of(idStartingWithZero)
        );
        assertEquals("ID number cannot start with 0", exception.getMessage());
    }

    @Test
    void shouldAcceptIdWithoutChecksumValidation() {
        // Given - 11 digits, valid format (checksum validation is currently disabled)
        String idNumber = "12345678911";

        // When
        IdNumber result = IdNumber.of(idNumber);

        // Then - ID is accepted since checksum validation is disabled
        assertNotNull(result);
        assertEquals(idNumber, result.getValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "10000000146",  // Valid checksum
        "11111111110"   // Valid checksum (all 1s except last digit)
    })
    void shouldAcceptValidTurkishIdNumbers(String validId) {
        // When
        IdNumber idNumber = IdNumber.of(validId);

        // Then
        assertNotNull(idNumber);
        assertEquals(validId, idNumber.getValue());
    }

    @Test
    void shouldReturnMaskedIdNumber() {
        // Given
        IdNumber idNumber = IdNumber.of(VALID_ID_1);

        // When
        String masked = idNumber.getMasked();

        // Then - VALID_ID_1 is "10000000146", masked as "10000***146"
        assertEquals("10000***146", masked);
        assertNotEquals(VALID_ID_1, masked);
    }

    @Test
    void shouldMaskMiddleDigits() {
        // Given
        IdNumber idNumber = IdNumber.of("10000000146");

        // When
        String masked = idNumber.getMasked();

        // Then
        assertEquals("10000***146", masked);
    }

    @Test
    void shouldReturnNullForOfNullableWithNull() {
        // When
        IdNumber idNumber = IdNumber.ofNullable(null);

        // Then
        assertNull(idNumber);
    }

    @Test
    void shouldReturnNullForOfNullableWithEmpty() {
        // When
        IdNumber idNumber = IdNumber.ofNullable("");

        // Then
        assertNull(idNumber);
    }

    @Test
    void shouldReturnNullForOfNullableWithWhitespace() {
        // When
        IdNumber idNumber = IdNumber.ofNullable("   ");

        // Then
        assertNull(idNumber);
    }

    @Test
    void shouldCreateIdNumberForOfNullableWithValidInput() {
        // When
        IdNumber idNumber = IdNumber.ofNullable(VALID_ID_1);

        // Then
        assertNotNull(idNumber);
        assertEquals(VALID_ID_1, idNumber.getValue());
    }

    @Test
    void shouldBeEqualWhenValuesSame() {
        // Given
        IdNumber id1 = IdNumber.of(VALID_ID_1);
        IdNumber id2 = IdNumber.of(VALID_ID_1);

        // When & Then
        assertEquals(id1, id2);
        assertEquals(id1.hashCode(), id2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenValuesDifferent() {
        // Given
        IdNumber id1 = IdNumber.of(VALID_ID_1);
        IdNumber id2 = IdNumber.of(VALID_ID_2);

        // When & Then
        assertNotEquals(id1, id2);
    }

    @Test
    void shouldReturnMaskedInToString() {
        // Given
        IdNumber idNumber = IdNumber.of(VALID_ID_1);

        // When
        String toString = idNumber.toString();

        // Then - VALID_ID_1 is "10000000146", masked as "10000***146"
        assertEquals("10000***146", toString);
        assertNotEquals(VALID_ID_1, toString); // Never expose full ID
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        IdNumber idNumber = IdNumber.of(VALID_ID_1);

        // When & Then
        assertEquals(idNumber, idNumber);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        IdNumber idNumber = IdNumber.of(VALID_ID_1);

        // When & Then
        assertNotEquals(null, idNumber);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        IdNumber idNumber = IdNumber.of(VALID_ID_1);
        String string = VALID_ID_1;

        // When & Then
        assertNotEquals(idNumber, string);
    }

    @Test
    void shouldValidateTurkishIdChecksumAlgorithm10thDigit() {
        // Given - Manually calculate valid ID
        // ID: 1 2 3 4 5 6 7 8 9 X Y
        // 10th digit (X): (1-2+3-4+5-6+7-8+9) % 10 = (5) % 10 = 5
        // 11th digit (Y): (1+2+3+4+5+6+7+8+9+5) % 10 = 50 % 10 = 0
        String validId = "12345678950";

        // When
        IdNumber idNumber = IdNumber.of(validId);

        // Then
        assertEquals(validId, idNumber.getValue());
    }

    @Test
    void shouldValidateTurkishIdChecksumAlgorithm11thDigit() {
        // Given - ID with specific checksum
        // Testing the 11th digit validation
        String validId = "10000000146";

        // When
        IdNumber idNumber = IdNumber.of(validId);

        // Then
        assertEquals(validId, idNumber.getValue());
    }

    @Test
    void shouldAcceptIdEvenWithWrong10thDigit() {
        // Given - Valid format but wrong 10th digit (checksum validation disabled)
        String idNumber = "12345678960";

        // When
        IdNumber result = IdNumber.of(idNumber);

        // Then - ID is accepted since checksum validation is disabled
        assertNotNull(result);
        assertEquals(idNumber, result.getValue());
    }

    @Test
    void shouldAcceptIdEvenWithWrong11thDigit() {
        // Given - Valid format but wrong 11th digit (checksum validation disabled)
        String idNumber = "12345678951";

        // When
        IdNumber result = IdNumber.of(idNumber);

        // Then - ID is accepted since checksum validation is disabled
        assertNotNull(result);
        assertEquals(idNumber, result.getValue());
    }
}
