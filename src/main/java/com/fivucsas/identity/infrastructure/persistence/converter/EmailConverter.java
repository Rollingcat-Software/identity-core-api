package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.Email;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA AttributeConverter for Email value object.
 * Converts between Email (domain) and String (database).
 *
 * Following principles:
 * - Adapter Pattern: Adapts domain to persistence layer
 * - Separation of Concerns: Domain doesn't know about JPA
 * - autoApply = true: Automatically used for all Email fields
 */
@Converter(autoApply = true)
public class EmailConverter implements AttributeConverter<Email, String> {

    @Override
    public String convertToDatabaseColumn(Email email) {
        if (email == null) {
            return null;
        }
        return email.getValue();
    }

    @Override
    public Email convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }
        return Email.of(dbData);
    }
}
