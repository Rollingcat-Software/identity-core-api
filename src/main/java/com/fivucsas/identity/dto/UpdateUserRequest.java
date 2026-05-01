package com.fivucsas.identity.dto;

import com.fivucsas.identity.entity.UserStatus;
import jakarta.validation.constraints.Email;
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
public class UpdateUserRequest {

    @Size(min = 2, max = 100, message = "First name must be between 2 and 100 characters")
    private String firstName;

    @Size(min = 2, max = 100, message = "Last name must be between 2 and 100 characters")
    private String lastName;

    @Email(message = "Invalid email format")
    private String email;

    @Pattern(regexp = "^[0-9]{11}$", message = "ID number must be 11 digits")
    private String idNumber;

    /**
     * Phone number in strict E.164 format (USER-BUG-4 follow-up).
     * Required prefix `+`, country-code first digit 1-9, total 10-15 digits.
     * Twilio Verify matches `to` + `code` byte-for-byte: a non-E.164 input
     * sends to one normalized number but verifies against the raw string
     * the server stored, producing a silent send-OK / verify-FAIL.
     * <p>
     * Error code: {@code phone.e164} — consumed by formatApiError in the web client.
     */
    @Pattern(regexp = "^\\+[1-9]\\d{9,14}$",
             message = "phone.e164: Phone number must be in E.164 format (e.g. +905551234567)")
    private String phoneNumber;

    @Size(max = 500, message = "Address must not exceed 500 characters")
    private String address;

    private UserStatus status;
}
