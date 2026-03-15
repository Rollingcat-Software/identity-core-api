package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.WebAuthnCredential;

import java.util.Optional;

/**
 * Output port for WebAuthnCredential persistence operations.
 */
public interface WebAuthnCredentialRepositoryPort {

    Optional<WebAuthnCredential> findByCredentialId(String credentialId);

    WebAuthnCredential save(WebAuthnCredential credential);
}
