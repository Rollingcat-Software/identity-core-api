package com.fivucsas.identity.application.dto.response;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Response for {@code POST /api/v1/tenants/{tenantId}/email-domains/{domain}/verification}
 * — the DNS-TXT ownership challenge the tenant admin must publish.
 *
 * <p>The admin creates a DNS TXT record with {@link #recordName} as the host
 * and {@link #recordValue} as the value, then calls the {@code /verify}
 * endpoint. Example:</p>
 * <pre>
 *   recordName : _fivucsas-verify.example.com
 *   recordType : TXT
 *   recordValue: fivucsas-domain-verification=Hk3...e9
 * </pre>
 */
@Getter
@Builder
public class DomainVerificationChallengeResponse {

    /** The email domain this challenge is for (lowercase FQDN, no '@'). */
    private final String domain;

    /** Whether the domain is already verified (challenge is a no-op then). */
    private final boolean verified;

    /** DNS host/name the admin must create the TXT record under. */
    private final String recordName;

    /** Always {@code "TXT"}. */
    private final String recordType;

    /** Exact TXT value: {@code fivucsas-domain-verification=<token>}. */
    private final String recordValue;

    /** When this token was (re)issued. */
    private final Instant requestedAt;

    /**
     * Human-readable instruction the UI can render verbatim, e.g.
     * "Add a TXT record for _fivucsas-verify.example.com with value
     * fivucsas-domain-verification=… then click Verify."
     */
    private final String instructions;
}
