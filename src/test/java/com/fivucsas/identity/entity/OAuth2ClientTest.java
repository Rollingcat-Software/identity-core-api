package com.fivucsas.identity.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OAuth2Client} business methods.
 *
 * <p>Primary focus: {@code isRedirectUriAllowed} and the JSON parsing of
 * {@code redirectUris}, which was previously a string-split parser that
 * corrupted URIs containing commas in query strings.
 */
@DisplayName("OAuth2Client Entity Tests")
class OAuth2ClientTest {

    private OAuth2Client withRedirects(String redirectUrisJson) {
        return OAuth2Client.builder()
                .clientId("test-client")
                .clientSecret("secret")
                .clientName("Test App")
                .redirectUris(redirectUrisJson)
                .build();
    }

    @Nested
    @DisplayName("isRedirectUriAllowed — exact JSON literal match")
    class ExactMatch {

        @Test
        @DisplayName("matches a simple HTTPS redirect URI")
        void exactHttpsMatch() {
            OAuth2Client client = withRedirects("[\"https://app.example.com/callback\"]");
            assertTrue(client.isRedirectUriAllowed("https://app.example.com/callback"));
            assertFalse(client.isRedirectUriAllowed("https://evil.example.com/callback"));
        }

        @Test
        @DisplayName("redirect URI with a comma in the query string is preserved by Jackson")
        void uriWithCommaInQueryString() {
            // Old string-split parser would have chopped this URI in half at the comma.
            OAuth2Client client = withRedirects("[\"https://example.com/cb?next=a,b\"]");
            assertTrue(client.isRedirectUriAllowed("https://example.com/cb?next=a,b"),
                    "Jackson must preserve commas inside query strings");
        }

        @Test
        @DisplayName("multiple redirects in one client")
        void multipleRedirects() {
            OAuth2Client client = withRedirects(
                    "[\"https://app.example.com/cb\",\"https://staging.example.com/cb\"]");
            assertTrue(client.isRedirectUriAllowed("https://app.example.com/cb"));
            assertTrue(client.isRedirectUriAllowed("https://staging.example.com/cb"));
            assertFalse(client.isRedirectUriAllowed("https://other.example.com/cb"));
        }

        @Test
        @DisplayName("malformed JSON falls back to empty list — never crashes, never over-matches")
        void malformedJsonReturnsEmpty() {
            OAuth2Client client = withRedirects("not-json-at-all");
            assertFalse(client.isRedirectUriAllowed("https://app.example.com/cb"));
        }

        @Test
        @DisplayName("null redirectUris is rejected safely")
        void nullIsRejected() {
            OAuth2Client client = withRedirects(null);
            assertFalse(client.isRedirectUriAllowed("https://app.example.com/cb"));
        }
    }

    @Nested
    @DisplayName("isRedirectUriAllowed — loopback redirect matching (RFC 8252 §7.3)")
    class LoopbackMatch {

        @Test
        @DisplayName("registered http://127.0.0.1/cb matches incoming with any ephemeral port")
        void loopbackPortIsIgnored() {
            OAuth2Client client = withRedirects("[\"http://127.0.0.1/cb\"]");
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:54123/cb"));
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:65535/cb"));
        }

        @Test
        @DisplayName("attacker cannot smuggle query params past registration without query")
        void queryStringAttackIsBlocked() {
            // Task requirement: registration "http://127.0.0.1/cb" MUST NOT match
            // "http://127.0.0.1:3000/cb?attacker_param=x" — the incoming URI adds
            // a query string not present in the registration.
            OAuth2Client client = withRedirects("[\"http://127.0.0.1/cb\"]");
            assertFalse(client.isRedirectUriAllowed("http://127.0.0.1:3000/cb?attacker_param=x"),
                    "Extra query params must not widen the loopback allowlist");
        }

        @Test
        @DisplayName("any incoming query string is rejected — no smuggling even on registered query")
        void anyIncomingQueryIsRejected() {
            // RFC 8252 §7.3 tightened: the loopback redirect match ignores query
            // entirely. Even if the registration declares a query, the incoming
            // URI must be query-free. This is the strictest interpretation and
            // matches the task spec (B5).
            OAuth2Client client = withRedirects("[\"http://127.0.0.1/cb?app=cli\"]");
            assertFalse(client.isRedirectUriAllowed("http://127.0.0.1:3000/cb?app=cli"));
            assertFalse(client.isRedirectUriAllowed("http://127.0.0.1:3000/cb?app=evil"));
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:3000/cb"),
                    "Path + host + scheme match with no incoming query is still accepted");
        }

        @Test
        @DisplayName("fragment is tolerated per RFC 8252 (client-side only)")
        void fragmentIsTolerated() {
            // Fragments never reach the server, so they cannot be used for
            // attacker smuggling in the redirect URI itself. They only affect
            // exact-string matching of the JSON registration, not loopback
            // relaxation — but if a client library appends "#_=_" (a known
            // Facebook SDK quirk), the loopback match still accepts it.
            OAuth2Client client = withRedirects("[\"http://127.0.0.1/cb\"]");
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:3000/cb#state"));
        }

        @Test
        @DisplayName("localhost hostname is rejected — IP literal only")
        void localhostIsRejected() {
            // RFC 8252 §7.3 recommends IP literal (127.0.0.1) because "localhost"
            // is a DNS name that can be hijacked. Dropping the localhost branch
            // closes that bypass.
            OAuth2Client client = withRedirects("[\"http://localhost/cb\"]");
            assertFalse(client.isRedirectUriAllowed("http://localhost:3000/cb"),
                    "localhost must not match — only 127.0.0.1 is allowed for loopback");
            assertFalse(client.isRedirectUriAllowed("http://127.0.0.1:3000/cb"),
                    "A registration using localhost must not match a 127.0.0.1 incoming URI either");
        }

        @Test
        @DisplayName("IPv6 loopback [::1] is rejected — IPv4 literal only per RFC 8252 §7.3")
        void ipv6LoopbackRejected() {
            // Task B5 tightening: the spec says IPv4 loopback literal only.
            // IPv6 [::1] and ::1 are both rejected to keep the allowlist
            // minimal and defensive against URI-parser divergence between
            // native-app HTTP clients.
            OAuth2Client clientIpv6 = withRedirects("[\"http://[::1]/cb\"]");
            assertFalse(clientIpv6.isRedirectUriAllowed("http://[::1]:4000/cb"),
                    "IPv6 loopback registration must not match — IPv4 127.0.0.1 only");
            OAuth2Client clientIpv4 = withRedirects("[\"http://127.0.0.1/cb\"]");
            assertFalse(clientIpv4.isRedirectUriAllowed("http://[::1]:4000/cb"),
                    "IPv6 loopback incoming must not match an IPv4 registration");
        }

        @Test
        @DisplayName("various ephemeral ports all accepted on 127.0.0.1")
        void variousPortsAccepted() {
            OAuth2Client client = withRedirects("[\"http://127.0.0.1/cb\"]");
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:1024/cb"));
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:8080/cb"));
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:54321/cb"));
            assertTrue(client.isRedirectUriAllowed("http://127.0.0.1:65535/cb"));
        }

        @Test
        @DisplayName("non-loopback IP does not hit loopback branch")
        void nonLoopbackIpIsRejected() {
            OAuth2Client client = withRedirects("[\"http://127.0.0.1/cb\"]");
            assertFalse(client.isRedirectUriAllowed("http://192.168.1.1:3000/cb"));
            assertFalse(client.isRedirectUriAllowed("http://10.0.0.1/cb"));
        }
    }
}
