package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Anonymous request to start a number-matching approve-login session for an
 * account.
 */
public record ApproveLoginCreateRequest(
        @NotBlank @Email String email
) {}
