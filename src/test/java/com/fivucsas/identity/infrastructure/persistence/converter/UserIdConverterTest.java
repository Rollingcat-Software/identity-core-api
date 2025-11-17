package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.UserId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for UserIdConverter.
 * Tests bidirectional conversion between UserId value object and UUID.
 */
class UserIdConverterTest {

    private UserIdConverter converter;

    @BeforeEach
    void setUp() {
        converter = new UserIdConverter();
    }

    @Test
    void shouldConvertUserIdToDatabaseColumn() {
        // Given
        UUID uuid = UUID.randomUUID();
        UserId userId = UserId.of(uuid);

        // When
        UUID dbValue = converter.convertToDatabaseColumn(userId);

        // Then
        assertEquals(uuid, dbValue);
    }

    @Test
    void shouldReturnNullWhenConvertingNullUserIdToDatabase() {
        // When
        UUID dbValue = converter.convertToDatabaseColumn(null);

        // Then
        assertNull(dbValue);
    }

    @Test
    void shouldConvertDatabaseColumnToUserId() {
        // Given
        UUID dbValue = UUID.randomUUID();

        // When
        UserId userId = converter.convertToEntityAttribute(dbValue);

        // Then
        assertNotNull(userId);
        assertEquals(dbValue, userId.getValue());
    }

    @Test
    void shouldReturnNullWhenConvertingNullDatabaseValue() {
        // When
        UserId userId = converter.convertToEntityAttribute(null);

        // Then
        assertNull(userId);
    }

    @Test
    void shouldBeReversible() {
        // Given
        UUID originalDbValue = UUID.randomUUID();

        // When - Convert to entity then back to database
        UserId userId = converter.convertToEntityAttribute(originalDbValue);
        UUID dbValue = converter.convertToDatabaseColumn(userId);

        // Then
        assertEquals(originalDbValue, dbValue);
    }

    @Test
    void shouldPreserveUUIDEquality() {
        // Given
        UUID uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        UserId userId = UserId.of(uuid);

        // When
        UUID dbValue = converter.convertToDatabaseColumn(userId);
        UserId roundTrip = converter.convertToEntityAttribute(dbValue);

        // Then
        assertEquals(userId, roundTrip);
        assertEquals(uuid, dbValue);
    }
}
