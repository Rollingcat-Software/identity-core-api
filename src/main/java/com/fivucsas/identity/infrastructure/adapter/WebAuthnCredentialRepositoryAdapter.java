package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.repository.WebAuthnCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class WebAuthnCredentialRepositoryAdapter implements WebAuthnCredentialRepositoryPort {

    private final WebAuthnCredentialRepository jpaRepository;

    @Override
    public Optional<WebAuthnCredential> findByCredentialId(String credentialId) {
        return jpaRepository.findByCredentialId(credentialId);
    }

    @Override
    public WebAuthnCredential save(WebAuthnCredential credential) {
        return jpaRepository.save(credential);
    }
}
