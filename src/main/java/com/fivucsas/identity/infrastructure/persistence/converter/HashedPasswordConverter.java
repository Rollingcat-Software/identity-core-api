package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.HashedPassword;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA AttributeConverter for HashedPassword value object.
 * Converts between HashedPassword (domain) and String (database).
 *
 * Security note: This converter handles ONLY hashed passwords.
 * The value object validates BCrypt hash format on conversion.
 */
@Converter(autoApply = true)
public class HashedPasswordConverter implements AttributeConverter<HashedPassword, String> {

    @Override
    public String convertToDatabaseColumn(HashedPassword password) {
        if (password == null) {
            return null;
        }
        return password.getValue();
    }

    @Override
    public HashedPassword convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }
        return HashedPassword.of(dbData);
    }
}
