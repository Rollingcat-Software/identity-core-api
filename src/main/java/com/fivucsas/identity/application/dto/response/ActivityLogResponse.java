package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Response DTO for user activity logs.
 *
 * Represents a single activity event in user's history.
 *
 * Following principles:
 * - Data Transfer Object pattern
 * - Immutable after construction
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActivityLogResponse {

    private String id;
    private String action;
    private String description;  // Human-readable description
    private String ipAddress;
    private String deviceInfo;   // Parsed from user agent
    private Boolean success;
    private String errorMessage;
    private Instant createdAt;

    /**
     * Generates human-readable description from action type.
     *
     * @param action the action type
     * @return human-readable description
     */
    public static String generateDescription(String action) {
        return switch (action) {
            case "USER_AUTHENTICATED" -> "Successful login";
            case "AUTHENTICATION_FAILED" -> "Failed login attempt";
            case "USER_REGISTERED" -> "Account created";
            case "USER_LOGGED_OUT" -> "Logged out";
            case "PASSWORD_RESET_REQUESTED" -> "Password reset requested";
            case "PASSWORD_RESET_SUCCESS" -> "Password changed successfully";
            case "EMAIL_VERIFIED" -> "Email verified";
            case "SESSION_REVOKED" -> "Session terminated";
            case "ALL_SESSIONS_REVOKED" -> "All other sessions terminated";
            case "ACCOUNT_LOCKED" -> "Account locked due to failed attempts";
            default -> action.replace("_", " ").toLowerCase();
        };
    }
}
