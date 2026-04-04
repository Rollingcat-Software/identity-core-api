package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.repository.WebAuthnCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class WebAuthnCredentialRepositoryAdapter implements WebAuthnCredentialRepositoryPort {

    private final WebAuthnCredentialRepository jpaRepository;

    @Override
    public Optional<WebAuthnCredential> findByCredentialId(String credentialId) {
        return jpaRepository.findByCredentialId(credentialId);
    }

    @Override
    public List<WebAuthnCredential> findAllByUserId(UUID userId) {
        return jpaRepository.findAllByUserId(userId);
    }

    @Override
    public boolean existsByCredentialId(String credentialId) {
        return jpaRepository.existsByCredentialId(credentialId);
    }

    @Override
    public void deleteByCredentialId(String credentialId) {
        jpaRepository.deleteByCredentialId(credentialId);
    }

    @Override
    public boolean existsById(UUID id) {
        return jpaRepository.existsById(id);
    }

    @Override
    public void deleteById(UUID id) {
        jpaRepository.deleteById(id);
    }

    @Override
    public WebAuthnCredential save(WebAuthnCredential credential) {
        return jpaRepository.save(credential);
    }
}
