package com.fivucsas.identity.application.service.mfa;

import java.util.Map;

/**
 * Input to {@link VerifyMfaStepService#execute(VerifyMfaStepRequest)}.
 * The controller is responsible for parsing the raw HTTP body and
 * extracting client-IP / User-Agent — this record is HTTP-agnostic.
 */
public record VerifyMfaStepRequest(
        String sessionToken,
        String method,
        Map<String, Object> data,
        String clientIp,
        String userAgent
) { }
