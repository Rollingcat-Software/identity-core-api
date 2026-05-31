package com.fivucsas.identity.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Identifier-first login pre-flight request: the email the user typed on the
 * identity step plus the hosted surface's OAuth client_id. Used by
 * {@code POST /api/v1/auth/login/preflight} to surface a tenant-mismatch error
 * on the email step (before the password step). NO password — this never
 * authenticates, it only checks tenant eligibility.
 */
public class LoginPreflightRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Schema(description = "The email entered on the identity step", example = "user@marmara.edu.tr")
    private String email;

    @Schema(description = "OAuth client_id of the hosted login surface (tenant-bound)", example = "marmara-bys-demo")
    private String clientId;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
