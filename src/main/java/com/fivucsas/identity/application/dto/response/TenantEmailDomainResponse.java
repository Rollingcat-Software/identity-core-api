package com.fivucsas.identity.application.dto.response;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Response DTO for a single tenant email-domain registry row
 * ({@code tenant_email_domains}, V44).
 */
@Getter
@Builder
public class TenantEmailDomainResponse {

    /** Lowercase FQDN, no '@' (e.g. {@code "marmara.edu.tr"}). */
    private final String domain;

    /**
     * Display/default hint only — exactly one per tenant. NOT a binding
     * priority: every domain a tenant owns binds identically on registration
     * (e.g. Marmara's {@code marmara.edu.tr} staff/academics and
     * {@code marun.edu.tr} students are peers).
     */
    private final boolean isPrimary;

    /**
     * True once domain ownership is proven (DNS-TXT verification or a trusted
     * admin/ROOT add). Only verified domains auto-bind other registrants /
     * satisfy {@code enforce_domain_matching}; self-service onboarding claims
     * start {@code false}. Surfaced so the admin UI shows status + offers the
     * "Verify domain" action on unverified rows.
     */
    private final boolean verified;

    private final Instant createdAt;
}
