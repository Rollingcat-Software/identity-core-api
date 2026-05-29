package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.DnsTxtLookupPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

/**
 * JNDI-based {@link DnsTxtLookupPort} implementation.
 *
 * <p>Resolves TXT records using the JDK's built-in {@code com.sun.jndi.dns}
 * provider — no third-party DNS dependency. This backs the DNS-TXT
 * domain-ownership verification flow: the verifier asks for the records at
 * {@code _fivucsas-verify.<domain>} and looks for
 * {@code fivucsas-domain-verification=<token>}.</p>
 *
 * <p>Failure handling: every ordinary "not found yet" condition — the name does
 * not exist ({@link NameNotFoundException}), the name exists but has no TXT
 * records, or the query times out — returns an EMPTY list rather than throwing,
 * because the calling verifier treats "no matching record" as simply "not
 * verified". A short read/connect timeout is configured so a slow or
 * unreachable resolver does not hang the request thread.</p>
 */
@Component
@Slf4j
public class JndiDnsTxtLookupAdapter implements DnsTxtLookupPort {

    private static final String DNS_FACTORY = "com.sun.jndi.dns.DnsContextFactory";

    /** Per-query timeout (ms) and retry count for the JNDI DNS provider. */
    private static final String DNS_TIMEOUT_MS = "3000";
    private static final String DNS_RETRIES = "1";

    @Override
    public List<String> lookupTxtRecords(String fqdn) {
        if (fqdn == null || fqdn.isBlank()) {
            return Collections.emptyList();
        }

        Hashtable<String, String> env = new Hashtable<>();
        env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, DNS_FACTORY);
        // dns:// with no authority uses the host's configured resolvers.
        env.put(javax.naming.Context.PROVIDER_URL, "dns:");
        env.put("com.sun.jndi.dns.timeout.initial", DNS_TIMEOUT_MS);
        env.put("com.sun.jndi.dns.timeout.retries", DNS_RETRIES);

        DirContext ctx = null;
        try {
            ctx = new InitialDirContext(env);
            Attributes attrs = ctx.getAttributes(fqdn, new String[] {"TXT"});
            Attribute txt = attrs.get("TXT");
            if (txt == null) {
                return Collections.emptyList();
            }
            List<String> values = new ArrayList<>(txt.size());
            for (int i = 0; i < txt.size(); i++) {
                Object value = txt.get(i);
                if (value != null) {
                    values.add(unquote(value.toString()));
                }
            }
            return values;
        } catch (NameNotFoundException e) {
            // No such DNS name (NXDOMAIN) or no TXT records — a normal
            // "not verified yet" outcome, not an error.
            log.debug("DNS TXT lookup found no record for '{}': {}", fqdn, e.getMessage());
            return Collections.emptyList();
        } catch (NamingException e) {
            // Timeout, SERVFAIL, transient resolver issue, etc. Treat as "not
            // verified" — the admin can retry. Logged at WARN for diagnostics.
            log.warn("DNS TXT lookup failed for '{}': {}", fqdn, e.getMessage());
            return Collections.emptyList();
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException ignored) {
                    // best-effort close
                }
            }
        }
    }

    /**
     * Strips the surrounding double-quotes the DNS provider wraps each TXT
     * character-string in. A TXT record split into multiple 255-byte chunks is
     * returned by JNDI as space-separated quoted chunks (e.g.
     * {@code "\"part1\" \"part2\""}); concatenate the chunk contents so a long
     * value compares correctly.
     */
    private static String unquote(String raw) {
        if (raw == null) {
            return "";
        }
        String trimmed = raw.trim();
        if (trimmed.indexOf('"') < 0) {
            return trimmed;
        }
        StringBuilder sb = new StringBuilder(trimmed.length());
        boolean inQuotes = false;
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (inQuotes) {
                sb.append(c);
            }
        }
        return sb.length() > 0 ? sb.toString() : trimmed;
    }
}
