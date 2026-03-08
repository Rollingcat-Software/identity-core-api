package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Response DTO for active user sessions.
 *
 * Represents a user's active session (refresh token) with device info.
 *
 * Following principles:
 * - Data Transfer Object pattern
 * - Immutable after construction
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionResponse {

    private String sessionId;
    private String ipAddress;
    private String userAgent;
    private String deviceInfo;  // Parsed from userAgent
    private Instant createdAt;
    private Instant expiryDate;
    private boolean isCurrent;  // Is this the current session?

    /**
     * Extracts simplified device info from user agent string.
     * Example: "Chrome on Windows", "Safari on iPhone"
     */
    public static String extractDeviceInfo(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown Device";
        }

        String browser = "Unknown Browser";
        String os = "Unknown OS";

        // Extract browser
        if (userAgent.contains("Chrome")) browser = "Chrome";
        else if (userAgent.contains("Firefox")) browser = "Firefox";
        else if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) browser = "Safari";
        else if (userAgent.contains("Edge")) browser = "Edge";
        else if (userAgent.contains("Opera")) browser = "Opera";

        // Extract OS
        if (userAgent.contains("Windows")) os = "Windows";
        else if (userAgent.contains("Mac OS")) os = "Mac";
        else if (userAgent.contains("Linux")) os = "Linux";
        else if (userAgent.contains("Android")) os = "Android";
        else if (userAgent.contains("iPhone") || userAgent.contains("iPad")) os = "iOS";

        return browser + " on " + os;
    }
}
