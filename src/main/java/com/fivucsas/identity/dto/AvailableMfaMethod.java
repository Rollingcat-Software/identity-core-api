package com.fivucsas.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents an auth method available to the user at a given MFA step.
 * Used in login responses to let the client render a method picker.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AvailableMfaMethod {
    private String methodType;
    private String name;
    private String category;
    private boolean enrolled;
    private boolean preferred;
    private boolean requiresEnrollment;
}
