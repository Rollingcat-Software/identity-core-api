package com.fivucsas.identity.infrastructure.oauth2;

import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PairwiseSubjectResolver} — Phase 4 of the Identity &amp;
 * Account-Linking design (flag-gated OIDC {@code sub} alignment).
 *
 * <p>The headline guarantees, asserted below:
 * <ul>
 *   <li><b>Default OFF is provably zero-change:</b> with the flag off, the subject
 *       equals {@code user.id} — the legacy value — exactly.</li>
 *   <li><b>Flag ON is pairwise:</b> stable across calls, different per relying
 *       party, opaque (never the raw {@code identity_id}), and keyed on the
 *       PERSON so the same identity gets the same sub across tenant accounts.</li>
 * </ul>
 */
class PairwiseSubjectResolverTest {

    private static final String SALT = "test-salt-9f3a";

    private User user(UUID userId, UUID identityId) {
        User u = mock(User.class);
        lenient().when(u.getId()).thenReturn(userId);
        lenient().when(u.getIdentityId()).thenReturn(identityId);
        return u;
    }

    private OAuth2Client client(String clientId, String redirectUri) {
        OAuth2Client c = mock(OAuth2Client.class);
        // sectorIdentifier() is a real method on the entity; mock it directly so
        // we don't depend on the JSON redirect_uris column shape here.
        lenient().when(c.sectorIdentifier()).thenReturn(sectorOf(redirectUri, clientId));
        return c;
    }

    private static String sectorOf(String redirectUri, String clientId) {
        if (redirectUri == null) return clientId;
        try {
            String host = java.net.URI.create(redirectUri).getHost();
            return host != null ? host.toLowerCase(java.util.Locale.ROOT) : clientId;
        } catch (RuntimeException e) {
            return clientId;
        }
    }

    // ---------------------------------------------------------------------
    // Flag OFF (default) — zero behaviour change
    // ---------------------------------------------------------------------

    @Test
    void flagOff_subjectIsExactlyLegacyUserId() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(false, SALT);
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        User user = user(userId, identityId);
        OAuth2Client client = client("rp-a", "https://app.rp-a.com/callback");

        String sub = resolver.resolveSubject(user, client);

        assertThat(resolver.isPairwiseEnabled()).isFalse();
        // The contract that makes the default safe to ship dormant.
        assertThat(sub).isEqualTo(userId.toString());
    }

    @Test
    void flagOff_ignoresIdentityIdAndClientEntirely() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(false, SALT);
        UUID userId = UUID.randomUUID();
        User user = user(userId, UUID.randomUUID());

        // Even with a null client (legacy userinfo token) the off-path is the
        // legacy user.id and never touches the client.
        String sub = resolver.resolveSubject(user, null);

        assertThat(sub).isEqualTo(userId.toString());
    }

    // ---------------------------------------------------------------------
    // Flag ON — pairwise pseudonymous subject
    // ---------------------------------------------------------------------

    @Test
    void flagOn_subjectIsStableAcrossCalls() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        User user = user(UUID.randomUUID(), UUID.randomUUID());
        OAuth2Client client = client("rp-a", "https://app.rp-a.com/callback");

        String first = resolver.resolveSubject(user, client);
        String second = resolver.resolveSubject(user, client);

        assertThat(first).isEqualTo(second);
    }

    @Test
    void flagOn_subjectIsNotTheRawIdentityIdAndIsOpaque() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        UUID identityId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        User user = user(userId, identityId);
        OAuth2Client client = client("rp-a", "https://app.rp-a.com/callback");

        String sub = resolver.resolveSubject(user, client);

        assertThat(sub)
                .isNotEqualTo(identityId.toString())   // raw identity_id never exposed
                .isNotEqualTo(userId.toString())       // not the user id either
                .doesNotContain(identityId.toString())
                .doesNotContain(userId.toString())
                .isNotBlank();
    }

    @Test
    void flagOn_differentRelyingPartiesGetUnlinkableSubjects() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        User user = user(UUID.randomUUID(), UUID.randomUUID());
        OAuth2Client rpA = client("rp-a", "https://app.rp-a.com/callback");
        OAuth2Client rpB = client("rp-b", "https://portal.rp-b.org/cb");

        String subA = resolver.resolveSubject(user, rpA);
        String subB = resolver.resolveSubject(user, rpB);

        // Pairwise per OIDC Core §8 — same person, two RPs, two unlinkable subs.
        assertThat(subA).isNotEqualTo(subB);
    }

    @Test
    void flagOn_samePersonSameRp_acrossTenantAccounts_yieldsSameSubject() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        UUID sharedIdentity = UUID.randomUUID();
        // Two DIFFERENT users (tenant memberships) for the SAME person.
        User membershipFivucsas = user(UUID.randomUUID(), sharedIdentity);
        User membershipMarmara = user(UUID.randomUUID(), sharedIdentity);
        OAuth2Client rp = client("rp-a", "https://app.rp-a.com/callback");

        String subViaFivucsas = resolver.resolveSubject(membershipFivucsas, rp);
        String subViaMarmara = resolver.resolveSubject(membershipMarmara, rp);

        // The whole point of Model A: one stable sub per (person, RP).
        assertThat(subViaFivucsas).isEqualTo(subViaMarmara);
    }

    @Test
    void flagOn_differentPeopleSameRp_yieldsDifferentSubjects() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        User personOne = user(UUID.randomUUID(), UUID.randomUUID());
        User personTwo = user(UUID.randomUUID(), UUID.randomUUID());
        OAuth2Client rp = client("rp-a", "https://app.rp-a.com/callback");

        assertThat(resolver.resolveSubject(personOne, rp))
                .isNotEqualTo(resolver.resolveSubject(personTwo, rp));
    }

    @Test
    void flagOn_saltChangesTheSubject() {
        UUID identityId = UUID.randomUUID();
        User user = user(UUID.randomUUID(), identityId);
        OAuth2Client rp = client("rp-a", "https://app.rp-a.com/callback");

        String subSaltA = new PairwiseSubjectResolver(true, "salt-A").resolveSubject(user, rp);
        String subSaltB = new PairwiseSubjectResolver(true, "salt-B").resolveSubject(user, rp);

        assertThat(subSaltA).isNotEqualTo(subSaltB);
    }

    @Test
    void flagOn_preBackfillNullIdentityId_keysOnUserIdWithoutNpe() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        UUID userId = UUID.randomUUID();
        User user = user(userId, null); // identity_id not yet backfilled (Phase 1 nullable)
        OAuth2Client rp = client("rp-a", "https://app.rp-a.com/callback");

        String sub = resolver.resolveSubject(user, rp);

        assertThat(sub)
                .isNotBlank()
                .isNotEqualTo(userId.toString())      // still hashed/opaque
                .doesNotContain(userId.toString());
        // Stable for that row across calls.
        assertThat(sub).isEqualTo(resolver.resolveSubject(user, rp));
    }

    @Test
    void flagOn_nullClient_degradesToStableSectorlessSubject_noNpe() {
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(true, SALT);
        User user = user(UUID.randomUUID(), UUID.randomUUID());

        // Legacy userinfo access token without a client_id claim → null client.
        String sub = resolver.resolveSubject(user, null);

        assertThat(sub).isNotBlank();
        assertThat(sub).isEqualTo(resolver.resolveSubject(user, null)); // stable
    }
}
