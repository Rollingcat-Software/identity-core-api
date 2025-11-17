package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.IdNumber;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA AttributeConverter for IdNumber value object.
 * Converts between IdNumber (domain) and String (database).
 *
 * The value object validates Turkish ID format on conversion.
 * Handles nullable ID numbers gracefully.
 */
@Converter(autoApply = true)
public class IdNumberConverter implements AttributeConverter<IdNumber, String> {

    @Override
    public String convertToDatabaseColumn(IdNumber idNumber) {
        if (idNumber == null) {
            return null;
        }
        return idNumber.getValue();
    }

    @Override
    public IdNumber convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }
        return IdNumber.of(dbData);
    }
}
