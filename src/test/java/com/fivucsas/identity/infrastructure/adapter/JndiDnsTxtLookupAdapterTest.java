package com.fivucsas.identity.infrastructure.adapter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JndiDnsTxtLookupAdapter Tests")
class JndiDnsTxtLookupAdapterTest {

    private final JndiDnsTxtLookupAdapter adapter = new JndiDnsTxtLookupAdapter();

    @Test
    @DisplayName("null / blank FQDN returns an empty list (never throws)")
    void blankInputReturnsEmpty() {
        assertThat(adapter.lookupTxtRecords(null)).isEmpty();
        assertThat(adapter.lookupTxtRecords("")).isEmpty();
        assertThat(adapter.lookupTxtRecords("   ")).isEmpty();
    }

    @Test
    @DisplayName("a non-resolving name returns an empty list rather than throwing")
    void nonexistentNameReturnsEmptyGracefully() {
        // A syntactically-valid name under .invalid (RFC 2606) that can never
        // resolve. The adapter must treat NXDOMAIN / timeout as "no record".
        List<String> records = adapter.lookupTxtRecords(
                "_fivucsas-verify.this-domain-definitely-does-not-exist.invalid");
        assertThat(records).isEmpty();
    }
}
