package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.UserId;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.UUID;

/**
 * JPA AttributeConverter for UserId value object.
 * Converts between UserId (domain) and UUID (database).
 *
 * Note: While JPA can handle UUID directly, this converter provides
 * type safety and prevents mixing different ID types.
 */
@Converter(autoApply = true)
public class UserIdConverter implements AttributeConverter<UserId, UUID> {

    @Override
    public UUID convertToDatabaseColumn(UserId userId) {
        if (userId == null) {
            return null;
        }
        return userId.getValue();
    }

    @Override
    public UserId convertToEntityAttribute(UUID dbData) {
        if (dbData == null) {
            return null;
        }
        return UserId.of(dbData);
    }
}
