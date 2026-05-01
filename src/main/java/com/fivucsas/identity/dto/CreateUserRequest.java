package com.fivucsas.identity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequest {

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 100, message = "First name must be between 2 and 100 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 100, message = "Last name must be between 2 and 100 characters")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    private String password;

    @Pattern(regexp = "^[0-9]{11}$", message = "ID number must be 11 digits")
    private String idNumber;

    /**
     * Phone number in strict E.164 format (USER-BUG-4 follow-up).
     * Required prefix `+`, country-code first digit 1-9, total 10-15 digits.
     * Matches {@code PhoneNumber} value-object regex so DB layer never rejects
     * what the controller accepted.
     * <p>
     * Error code: {@code phone.e164} — consumed by formatApiError in the web client.
     */
    @Pattern(regexp = "^\\+[1-9]\\d{9,14}$",
             message = "phone.e164: Phone number must be in E.164 format (e.g. +905551234567)")
    private String phoneNumber;

    @Size(max = 500, message = "Address must not exceed 500 characters")
    private String address;

    private String role; // Optional - role name to assign after creation

    private String tenantId; // Optional - tenant to assign user to
}
