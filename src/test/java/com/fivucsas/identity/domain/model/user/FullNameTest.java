package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FullName value object.
 * Tests name validation and formatting.
 */
class FullNameTest {

    @Test
    void shouldCreateValidFullName() {
        // When
        FullName name = FullName.of("John", "Doe");

        // Then
        assertNotNull(name);
        assertEquals("John", name.getFirstName());
        assertEquals("Doe", name.getLastName());
        assertEquals("John Doe", name.getFullName());
    }

    @Test
    void shouldTrimWhitespace() {
        // Given
        String firstNameWithSpaces = "  John  ";
        String lastNameWithSpaces = "  Doe  ";

        // When
        FullName name = FullName.of(firstNameWithSpaces, lastNameWithSpaces);

        // Then
        assertEquals("John", name.getFirstName());
        assertEquals("Doe", name.getLastName());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void shouldRejectNullOrEmptyFirstName(String invalidFirstName) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> FullName.of(invalidFirstName, "Doe")
        );
        assertTrue(exception.getMessage().contains("First name cannot be null or empty"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void shouldRejectNullOrEmptyLastName(String invalidLastName) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> FullName.of("John", invalidLastName)
        );
        assertTrue(exception.getMessage().contains("Last name cannot be null or empty"));
    }

    @Test
    void shouldRejectFirstNameExceedingMaxLength() {
        // Given - name with 101 characters
        String tooLongName = "a".repeat(101);

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> FullName.of(tooLongName, "Doe")
        );
        assertTrue(exception.getMessage().contains("First name cannot exceed 100 characters"));
    }

    @Test
    void shouldRejectLastNameExceedingMaxLength() {
        // Given - name with 101 characters
        String tooLongName = "a".repeat(101);

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> FullName.of("John", tooLongName)
        );
        assertTrue(exception.getMessage().contains("Last name cannot exceed 100 characters"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "John123",      // Contains numbers
        "John@Doe",     // Contains special char
        "John_Doe",     // Contains underscore
        "John#Doe"      // Contains hash
    })
    void shouldRejectFirstNameWithInvalidCharacters(String invalidFirstName) {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> FullName.of(invalidFirstName, "Doe")
        );
        assertTrue(exception.getMessage().contains("contains invalid characters"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "John",
        "Mary-Jane",        // Hyphenated name
        "O'Brien",          // Apostrophe
        "Jean-Claude",      // Hyphenated
        "José",             // Accented character
        "François",         // Accented character
        "Müller",           // Umlaut
        "Øystein",          // Nordic character
        "Władysław"         // Polish character
    })
    void shouldAcceptValidFirstNames(String validFirstName) {
        // When
        FullName name = FullName.of(validFirstName, "Doe");

        // Then
        assertNotNull(name);
        assertEquals(validFirstName, name.getFirstName());
    }

    @Test
    void shouldReturnFullName() {
        // Given
        FullName name = FullName.of("John", "Doe");

        // When
        String fullName = name.getFullName();

        // Then
        assertEquals("John Doe", fullName);
    }

    @Test
    void shouldReturnInitials() {
        // Given
        FullName name = FullName.of("John", "Doe");

        // When
        String initials = name.getInitials();

        // Then
        assertEquals("JD", initials);
    }

    @Test
    void shouldReturnFormattedName() {
        // Given
        FullName name = FullName.of("john", "doe");

        // When
        String formatted = name.getFormattedName();

        // Then
        assertEquals("DOE, John", formatted);
    }

    @Test
    void shouldReturnFormattedNameWithMixedCase() {
        // Given
        FullName name = FullName.of("JOHN", "DOE");

        // When
        String formatted = name.getFormattedName();

        // Then
        assertEquals("DOE, John", formatted);
    }

    @Test
    void shouldBeEqualWhenNamesSame() {
        // Given
        FullName name1 = FullName.of("John", "Doe");
        FullName name2 = FullName.of("John", "Doe");

        // When & Then
        assertEquals(name1, name2);
        assertEquals(name1.hashCode(), name2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenFirstNameDifferent() {
        // Given
        FullName name1 = FullName.of("John", "Doe");
        FullName name2 = FullName.of("Jane", "Doe");

        // When & Then
        assertNotEquals(name1, name2);
    }

    @Test
    void shouldNotBeEqualWhenLastNameDifferent() {
        // Given
        FullName name1 = FullName.of("John", "Doe");
        FullName name2 = FullName.of("John", "Smith");

        // When & Then
        assertNotEquals(name1, name2);
    }

    @Test
    void shouldReturnFullNameInToString() {
        // Given
        FullName name = FullName.of("John", "Doe");

        // When
        String toString = name.toString();

        // Then
        assertEquals("John Doe", toString);
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        FullName name = FullName.of("John", "Doe");

        // When & Then
        assertEquals(name, name);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        FullName name = FullName.of("John", "Doe");

        // When & Then
        assertNotEquals(null, name);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        FullName name = FullName.of("John", "Doe");
        String string = "John Doe";

        // When & Then
        assertNotEquals(name, string);
    }

    @Test
    void shouldHandleNamesWithSpaces() {
        // Given - Names with internal spaces
        FullName name = FullName.of("Mary Jane", "van der Berg");

        // When & Then
        assertEquals("Mary Jane", name.getFirstName());
        assertEquals("van der Berg", name.getLastName());
        assertEquals("Mary Jane van der Berg", name.getFullName());
    }

    @Test
    void shouldHandleNamesWithCommas() {
        // Given - Names with commas (like "Jr., Sr.")
        FullName name = FullName.of("John, Jr.", "Doe");

        // When & Then
        assertEquals("John, Jr.", name.getFirstName());
        assertEquals("Doe", name.getLastName());
    }

    @Test
    void shouldHandleNamesWithPeriods() {
        // Given - Names with periods (like "Dr.")
        FullName name = FullName.of("Dr. John", "Doe");

        // When & Then
        assertEquals("Dr. John", name.getFirstName());
        assertEquals("Doe", name.getLastName());
    }
}
