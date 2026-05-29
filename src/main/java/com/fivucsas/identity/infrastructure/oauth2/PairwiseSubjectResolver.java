package com.fivucsas.identity.infrastructure.oauth2;

import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

/**
 * Resolves the OIDC {@code sub} (subject) claim for id_tokens and the
 * {@code /oauth2/userinfo} response — Phase 4 of the Identity &amp; Account-Linking
 * design (see {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md}).
 *
 * <h2>Flag-gated, default OFF</h2>
 * Behaviour is governed by {@code app.identity.oidc-subject-identity}
 * (default {@code false}). This component is the SINGLE place that decides the
 * subject value for the OIDC surfaces, so the legacy and the new behaviour stay
 * in lockstep across id_token minting and userinfo.
 *
 * <ul>
 *   <li><b>Flag OFF (default, prod today):</b> {@link #resolveSubject} returns
 *       exactly {@code user.getId().toString()} — byte-identical to the legacy
 *       code path. Zero behaviour change; ships dormant.</li>
 *   <li><b>Flag ON:</b> the subject becomes an identity-derived, <b>pairwise</b>
 *       pseudonymous identifier per relying party (OpenID Connect Core 1.0 §8 —
 *       Pairwise Pseudonymous Identifiers). The same person presents a
 *       <i>stable</i> {@code sub} to a given RP across all their tenant accounts
 *       (because it is keyed by the platform {@code identity_id}, not the
 *       per-tenant {@code users.id}), while different RPs receive
 *       <i>unlinkable</i> subjects.</li>
 * </ul>
 *
 * <h2>Pairwise algorithm (flag ON)</h2>
 * <pre>
 *   sector       = client.sectorIdentifier()          // OIDC Core §8.1: host of the
 *                                                      //   registered redirect_uri,
 *                                                      //   else clientId
 *   localAccount = user.getIdentityId()               // the PERSON, cross-tenant
 *                  (or user.getId() pre-backfill,     //   so the same person → same
 *                   when identity_id is still NULL)    //   sub across their tenants
 *   sub          = base64url( SHA-256( sector + "|" + localAccount + "|" + salt ) )
 * </pre>
 *
 * <p>Properties:
 * <ul>
 *   <li><b>Deterministic / stable:</b> same (identity, RP) → same {@code sub}
 *       on every call.</li>
 *   <li><b>Per-RP unlinkable:</b> different sector identifiers → different
 *       {@code sub} for the same identity; two RPs cannot correlate the user.</li>
 *   <li><b>Opaque:</b> the SHA-256 digest never exposes the raw
 *       {@code identity_id} (one-way), and the salt frustrates dictionary attacks
 *       against the small UUID space.</li>
 * </ul>
 *
 * <p>The salt is read from {@code app.identity.pairwise-salt}; keep it stable and
 * secret per environment — rotating it rotates every pairwise {@code sub}.</p>
 *
 * <p>Pre-backfill safety: Phase 1 leaves {@code users.identity_id} nullable. If a
 * row has not yet been backfilled when the flag is on, this resolver keys on the
 * user id instead of NPE-ing — the sub is still stable + pairwise for that row,
 * it just won't yet be shared across the person's other tenant accounts until the
 * V67 backfill links them. This is logged at debug once per call.</p>
 */
@Component
@Slf4j
public class PairwiseSubjectResolver {

    private final boolean pairwiseEnabled;
    private final String salt;

    public PairwiseSubjectResolver(
            @Value("${app.identity.oidc-subject-identity:false}") boolean pairwiseEnabled,
            @Value("${app.identity.pairwise-salt:}") String salt) {
        this.pairwiseEnabled = pairwiseEnabled;
        this.salt = salt != null ? salt : "";
        if (pairwiseEnabled) {
            log.info("OIDC pairwise subject identity is ENABLED "
                    + "(app.identity.oidc-subject-identity=true) — sub is now an "
                    + "identity-derived pairwise pseudonym per relying party.");
        }
    }

    /** @return true when the pairwise-subject flag is on. Exposed for tests/diagnostics. */
    public boolean isPairwiseEnabled() {
        return pairwiseEnabled;
    }

    /**
     * Resolves the OIDC subject for the given user + relying party.
     *
     * @param user   the authenticated user (tenant membership row)
     * @param client the relying party / OAuth2 client the token is minted for;
     *               may be {@code null} only on the userinfo path for an in-flight
     *               access token minted before the {@code client_id} claim existed
     * @return the legacy {@code user.id} string when the flag is off, otherwise the
     *         pairwise pseudonymous subject
     */
    public String resolveSubject(User user, OAuth2Client client) {
        if (!pairwiseEnabled) {
            // Default path — byte-identical to the pre-Phase-4 behaviour.
            return user.getId().toString();
        }
        return computePairwiseSubject(user, client);
    }

    private String computePairwiseSubject(User user, OAuth2Client client) {
        // client is null only for a legacy userinfo access token (pre-deploy)
        // missing the client_id claim — degrade to an empty sector so the sub is
        // still stable + opaque (it just isn't per-RP for that one legacy token).
        String sector = client != null ? client.sectorIdentifier() : "";

        // Key on the PERSON (identity_id) so the sub is stable across the person's
        // tenant accounts. Fall back to the user id pre-backfill (identity_id NULL).
        UUID identityId = user.getIdentityId();
        String localAccount;
        if (identityId != null) {
            localAccount = identityId.toString();
        } else {
            localAccount = user.getId().toString();
            log.debug("Pairwise sub: user {} has no identity_id yet (pre-backfill) — "
                    + "keying on user id; sub will link across tenants after V67 backfill.",
                    user.getId());
        }

        String material = sector + "|" + localAccount + "|" + salt;
        return base64UrlSha256(material);
    }

    private static String base64UrlSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS — unreachable on any compliant JVM.
            throw new IllegalStateException("SHA-256 unavailable for pairwise subject derivation", e);
        }
    }
}
