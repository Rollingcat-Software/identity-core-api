package com.fivucsas.identity.service;

import com.fivucsas.identity.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Commits a refresh-token rotation-family revocation in its OWN transaction.
 *
 * <p><b>SECURITY (2026-06-01, LOGIC_AUDIT P0-4).</b> RFC 6749 §10.4 reuse-detection
 * revokes the whole rotation family when a replayed/revoked refresh token is presented,
 * then throws {@link com.fivucsas.identity.domain.exception.TokenRevokedException} to
 * reject the request. But the revoke ran inside the SAME {@code @Transactional} as the
 * throwing caller ({@code verifyExpiration} ← {@code RefreshAccessTokenService.execute},
 * one physical transaction), so Spring marked it rollback-only and undid the UPDATE — the
 * family stayed valid and a stolen sibling token kept minting access tokens (while the
 * audit row, persisted via a REQUIRES_NEW path, misleadingly claimed the family was
 * revoked). Red-team-confirmed live on 2026-06-01.
 *
 * <p>This helper runs the revoke in {@link Propagation#REQUIRES_NEW} so it COMMITS
 * independently of the caller's rollback-on-throw. It MUST be a separate bean so the call
 * goes through the Spring proxy — a self-invocation would not start a new transaction.
 */
@Component
@RequiredArgsConstructor
public class RefreshTokenFamilyRevoker {

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int revokeFamily(UUID familyId) {
        return refreshTokenRepository.revokeFamily(familyId, Instant.now());
    }
}
