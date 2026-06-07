package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.RefreshToken;

import java.util.Map;

/**
 * Output port for minting the OAuth 2.0 / OIDC token-endpoint response body
 * (access_token + id_token + optional refresh_token) for {@code OAuth2Service}.
 *
 * <p><b>Why this port exists (hexagonal boundary).</b> Building the token
 * response requires the resource owner's profile fields (email, tenant,
 * name, email/phone verification flags) and the managed JPA {@code users} row
 * (the refresh token's FK + the pairwise-subject {@code identity_id}). The JPA
 * {@code entity.User} type is fenced behind the {@code UserDomainBoundaryTest}
 * ArchUnit ratchet and MUST NOT be imported from {@code application..}. This
 * port exposes only plain DTOs / {@link Map}s and the already-allowed
 * {@code entity.OAuth2Client} / {@code entity.RefreshToken} types, so the
 * application service stays boundary-clean. The implementing adapter lives in
 * {@code infrastructure..} (the official bridge) and is the only place that
 * touches {@code entity.User} for the token mint — mirroring the
 * {@code MembershipSwitchPort} / {@code MembershipSwitchAdapter} pattern.</p>
 */
public interface OAuth2TokenMintPort {

    /**
     * Mints the RFC 6749 §5.1 token-endpoint success body for the
     * {@code authorization_code} grant: {@code access_token}, {@code token_type},
     * {@code expires_in}, {@code id_token}, a freshly minted {@code refresh_token}
     * (RFC 6749 §6) + {@code refresh_expires_in}, and the {@code scope} (when set).
     *
     * <p>The resource owner is resolved by email inside the adapter (the only
     * {@code entity.User} access), so the application service never inspects the
     * JPA entity.</p>
     *
     * @param userEmail  the authenticated resource owner's email (the token subject)
     * @param client     the OAuth2 client (relying party) the tokens are for
     * @param scope      space-delimited granted scopes (drives OIDC claims)
     * @param nonce      OIDC nonce to echo into the id_token (nullable/empty)
     * @param ipAddress  caller IP recorded on the refresh token (audit)
     * @param userAgent  caller User-Agent recorded on the refresh token (audit)
     * @return the RFC 6749 §5.1 token response map (with a fresh refresh_token)
     * @throws IllegalArgumentException if no user resolves for {@code userEmail}
     */
    Map<String, Object> mintForAuthorizationCode(
            String userEmail,
            OAuth2Client client,
            String scope,
            String nonce,
            String ipAddress,
            String userAgent);

    /**
     * Mints the RFC 6749 §5.1 token body for the {@code refresh_token} grant —
     * the access_token + id_token portion only (the caller rotates the refresh
     * token itself and appends {@code refresh_token} / {@code refresh_expires_in}).
     *
     * <p>Resolves the resource owner from the presented (still-valid) refresh
     * token, enforces the tenant-active guard (parity with the legacy
     * {@code /auth/refresh} path — a suspended tenant cannot keep a session alive
     * by refreshing), then builds the response. All {@code entity.User} access
     * happens here.</p>
     *
     * @param existing   the validated (not-yet-rotated) presented refresh token
     * @param client     the requesting OAuth2 client
     * @param scope      space-delimited granted scopes to re-grant
     * @param ipAddress  caller IP (audit; the caller's rotation records the row)
     * @param userAgent  caller User-Agent (audit)
     * @return the access_token + id_token response map (NO refresh_token — the
     *         caller appends the rotated token)
     * @throws com.fivucsas.identity.domain.exception.TenantSuspendedException
     *         when the resource owner's tenant is not ACTIVE
     */
    Map<String, Object> mintForRefreshGrant(
            RefreshToken existing,
            OAuth2Client client,
            String scope,
            String ipAddress,
            String userAgent);
}
