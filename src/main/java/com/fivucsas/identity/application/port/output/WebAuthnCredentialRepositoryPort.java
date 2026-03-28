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

    List<WebAuthnCredential> findAllByUserId(UUID userId);

    boolean existsByCredentialId(String credentialId);

    void deleteByCredentialId(String credentialId);

    WebAuthnCredential save(WebAuthnCredential credential);
}
