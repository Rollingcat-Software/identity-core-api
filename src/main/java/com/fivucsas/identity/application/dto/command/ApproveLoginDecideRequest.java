package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Authenticated approver's decision for a number-matching approve-login
 * session. {@code matchNumber} is the two-digit number the approver's device
 * shows; it must equal the session's number on {@code allow}.
 */
public record ApproveLoginDecideRequest(
        @NotBlank @Pattern(regexp = "allow|deny") String decision,
        String matchNumber
) {}
