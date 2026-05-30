package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.WebAuthnCredential;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for WebAuthnCredential persistence operations.
 */
public interface WebAuthnCredentialRepositoryPort {

    Optional<WebAuthnCredential> findByCredentialId(String credentialId);

    Optional<WebAuthnCredential> findById(UUID id);

    List<WebAuthnCredential> findAllByUserId(UUID userId);

    /**
     * Finds every credential bound to the given WebAuthn user handle
     * (base64url-encoded). Used by the usernameless/discoverable assertion path
     * to resolve a user from the handle the authenticator returns.
     */
    List<WebAuthnCredential> findAllByUserHandle(String userHandle);

    boolean existsByCredentialId(String credentialId);

    void deleteByCredentialId(String credentialId);

    boolean existsById(UUID id);

    void deleteById(UUID id);

    WebAuthnCredential save(WebAuthnCredential credential);
}
