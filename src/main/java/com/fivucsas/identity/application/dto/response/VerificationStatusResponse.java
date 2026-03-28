package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.VerificationLevel;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record VerificationStatusResponse(
    UUID userId,
    boolean identityVerified,
    VerificationLevel verificationLevel,
    Instant identityVerifiedAt,
    List<VerificationSessionResponse> sessions
) {}
