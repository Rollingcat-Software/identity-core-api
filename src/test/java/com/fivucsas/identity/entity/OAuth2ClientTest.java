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
}
