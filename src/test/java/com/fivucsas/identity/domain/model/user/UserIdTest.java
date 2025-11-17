package com.fivucsas.identity.domain.model.user;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for UserId value object.
 * Tests UUID generation and conversion.
 */
class UserIdTest {

    @Test
    void shouldGenerateRandomUserId() {
        // When
        UserId userId1 = UserId.generate();
        UserId userId2 = UserId.generate();

        // Then
        assertNotNull(userId1);
        assertNotNull(userId2);
        assertNotEquals(userId1, userId2); // Different random UUIDs
    }

    @Test
    void shouldCreateUserIdFromUUID() {
        // Given
        UUID uuid = UUID.randomUUID();

        // When
        UserId userId = UserId.of(uuid);

        // Then
        assertNotNull(userId);
        assertEquals(uuid, userId.getValue());
    }

    @Test
    void shouldCreateUserIdFromValidString() {
        // Given
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";

        // When
        UserId userId = UserId.of(validUuid);

        // Then
        assertNotNull(userId);
        assertEquals(validUuid, userId.getValue().toString());
    }

    @Test
    void shouldRejectNullUUID() {
        // When & Then
        NullPointerException exception = assertThrows(
            NullPointerException.class,
            () -> UserId.of((UUID) null)
        );
        assertEquals("UserId cannot be null", exception.getMessage());
    }

    @Test
    void shouldRejectInvalidStringFormat() {
        // Given
        String invalidUuid = "not-a-valid-uuid";

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> UserId.of(invalidUuid)
        );
        assertTrue(exception.getMessage().contains("Invalid UserId format"));
    }

    @Test
    void shouldRejectEmptyString() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> UserId.of("")
        );
        assertTrue(exception.getMessage().contains("Invalid UserId format"));
    }

    @Test
    void shouldRejectNullString() {
        // When & Then
        assertThrows(
            NullPointerException.class,
            () -> UserId.of((String) null)
        );
    }

    @Test
    void shouldBeEqualWhenUUIDsSame() {
        // Given
        UUID uuid = UUID.randomUUID();
        UserId userId1 = UserId.of(uuid);
        UserId userId2 = UserId.of(uuid);

        // When & Then
        assertEquals(userId1, userId2);
        assertEquals(userId1.hashCode(), userId2.hashCode());
    }

    @Test
    void shouldNotBeEqualWhenUUIDsDifferent() {
        // Given
        UserId userId1 = UserId.generate();
        UserId userId2 = UserId.generate();

        // When & Then
        assertNotEquals(userId1, userId2);
    }

    @Test
    void shouldReturnUUIDStringInToString() {
        // Given
        UUID uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        UserId userId = UserId.of(uuid);

        // When
        String toString = userId.toString();

        // Then
        assertEquals("550e8400-e29b-41d4-a716-446655440000", toString);
    }

    @Test
    void shouldBeSameInstance() {
        // Given
        UserId userId = UserId.generate();

        // When & Then
        assertEquals(userId, userId);
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        UserId userId = UserId.generate();

        // When & Then
        assertNotEquals(null, userId);
    }

    @Test
    void shouldNotBeEqualToDifferentClass() {
        // Given
        UserId userId = UserId.generate();
        UUID uuid = userId.getValue();

        // When & Then
        assertNotEquals(userId, uuid);
    }

    @Test
    void shouldCreateFromStringAndBeEqual() {
        // Given
        String uuidString = "550e8400-e29b-41d4-a716-446655440000";
        UUID uuid = UUID.fromString(uuidString);

        // When
        UserId userId1 = UserId.of(uuidString);
        UserId userId2 = UserId.of(uuid);

        // Then
        assertEquals(userId1, userId2);
    }

    @Test
    void shouldPreventValueModification() {
        // Given
        UUID originalUuid = UUID.randomUUID();
        UserId userId = UserId.of(originalUuid);

        // When - Get reference
        UUID retrievedUuid = userId.getValue();

        // Then - Original should remain unchanged (UUID is immutable)
        assertEquals(originalUuid, userId.getValue());
        assertEquals(retrievedUuid, userId.getValue());
    }
}
