package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.domain.model.user.FullName;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA AttributeConverter for FullName value object.
 * Converts between FullName (domain) and String (database).
 *
 * Format: "FirstName|LastName" (pipe-delimited)
 *
 * NOTE: This is a simplified approach. For production, consider:
 * - Using @Embedded with separate firstName/lastName columns
 * - JSON serialization
 * - Composite value object
 *
 * Current approach chosen for simplicity while maintaining value object benefits.
 */
@Converter(autoApply = true)
public class FullNameConverter implements AttributeConverter<FullName, String> {

    private static final String DELIMITER = "|";

    @Override
    public String convertToDatabaseColumn(FullName fullName) {
        if (fullName == null) {
            return null;
        }
        return fullName.getFirstName() + DELIMITER + fullName.getLastName();
    }

    @Override
    public FullName convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }

        String[] parts = dbData.split("\\" + DELIMITER, 2);
        if (parts.length != 2) {
            throw new IllegalStateException(
                "Invalid FullName format in database: " + dbData +
                ". Expected format: 'FirstName|LastName'"
            );
        }

        return FullName.of(parts[0], parts[1]);
    }
}
