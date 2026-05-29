package com.fivucsas.identity.application.port.output;

import java.util.List;

/**
 * Output port for resolving DNS TXT records.
 *
 * <p>Used by the DNS-TXT domain-ownership verification flow
 * ({@code TenantEmailDomainController}'s {@code /verify} endpoint): the
 * application asks for the TXT records at {@code _fivucsas-verify.<domain>}
 * and checks whether the expected
 * {@code fivucsas-domain-verification=<token>} value is present.</p>
 *
 * <p>Hexagonal Architecture — the application defines what it needs (a TXT
 * lookup); the infrastructure provides the JNDI/DNS implementation
 * ({@code JndiDnsTxtLookupAdapter}). Defining it as a port keeps the verifier
 * service unit-testable with an in-memory fake (no real DNS in tests).</p>
 */
public interface DnsTxtLookupPort {

    /**
     * Resolves all TXT records for the given fully-qualified DNS name.
     *
     * <p>Implementations MUST NOT throw on the ordinary "no such name" /
     * "no TXT records" / timeout cases — those are normal "not verified yet"
     * outcomes and should return an empty list. Only genuinely unexpected
     * conditions may propagate.</p>
     *
     * <p>Each returned string is one TXT record's full character-string value,
     * already unquoted (surrounding double-quotes stripped) and with any
     * multi-chunk record concatenated. The order is unspecified.</p>
     *
     * @param fqdn the DNS name to query (e.g. {@code "_fivucsas-verify.example.com"});
     *             never {@code null} or blank
     * @return the TXT record values found, or an empty list if the name does
     *         not resolve, has no TXT records, or the lookup timed out
     */
    List<String> lookupTxtRecords(String fqdn);
}
