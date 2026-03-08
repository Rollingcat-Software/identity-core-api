package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Response DTO for API keys.
 *
 * Note: Full API key is shown ONLY once during creation.
 * Subsequent responses show only the prefix.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKeyResponse {

    private String id;
    private String name;
    private String prefix;  // First 8 chars (e.g., "fiv_1234")
    private String fullKey;  // Shown ONLY on creation (e.g., "fiv_1234567890abcdef...")
    private String[] scopes;
    private Instant expiresAt;
    private Instant lastUsedAt;
    private boolean isActive;
    private Instant createdAt;
    private String message;  // Instructions/warnings
}
