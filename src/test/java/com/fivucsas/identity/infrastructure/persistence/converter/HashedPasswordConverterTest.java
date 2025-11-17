package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.HashedPassword;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HashedPasswordConverter.
 * Tests bidirectional conversion between HashedPassword value object and String.
 */
class HashedPasswordConverterTest {

    private HashedPasswordConverter converter;
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @BeforeEach
    void setUp() {
        converter = new HashedPasswordConverter();
    }

    @Test
    void shouldConvertHashedPasswordToDatabaseColumn() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When
        String dbValue = converter.convertToDatabaseColumn(password);

        // Then
        assertEquals(VALID_BCRYPT_HASH, dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullPasswordToDatabase() {
        // When
        String dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToHashedPassword() {
        // Given
        String dbValue = VALID_BCRYPT_HASH;

        // When
        HashedPassword password = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(password);
        assertEquals(VALID_BCRYPT_HASH, password.getValue());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        HashedPassword password = converter.convertToEntityAttribute(null);

        // Then
        assertNull(password);
    }

    @Test
    void shouldBeReversible() {
        // Given
        String originalDbValue = VALID_BCRYPT_HASH;

        // When - Convert to entity then back to database
        HashedPassword password = converter.convertToEntityAttribute(originalDbValue);
        String dbValue = converter.convertToDatabaseColumn(password);

        // Then
        assertEquals(originalDbValue, dbValue);
    }

    @Test
    void shouldPreserveHashIntegrity() {
        // Given
        HashedPassword password = HashedPassword.of(VALID_BCRYPT_HASH);

        // When
        String dbValue = converter.convertToDatabaseColumn(password);
        HashedPassword roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then - Hash should be identical after round trip
        assertEquals(password, roundTrip);
        assertEquals(60, dbValue.length()); // BCrypt hashes are always 60 chars
    }
}
