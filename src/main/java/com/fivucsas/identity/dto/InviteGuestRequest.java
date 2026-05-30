package com.fivucsas.identity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for creating a guest invitation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InviteGuestRequest {

    @NotBlank(message = "Guest email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotNull(message = "Access duration is required")
    @Min(value = 1, message = "Access duration must be at least 1 hour")
    private Integer accessDurationHours;

    private String message;

    /**
     * BCP-47 language tag for the invitation email ("tr" or "en"). Optional —
     * the admin UI passes the recipient's preferred language (or its own active
     * language) so the guest receives the email in their language. Null/blank or
     * any unsupported value falls back to English.
     */
    private String locale;
}
