package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.repository.OAuth2ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class OAuth2ClientRepositoryAdapter implements OAuth2ClientRepositoryPort {

    private final OAuth2ClientRepository jpaRepository;

    @Override
    public Optional<OAuth2Client> findByClientIdAndActiveTrue(String clientId) {
        return jpaRepository.findByClientIdAndActiveTrue(clientId);
    }

    @Override
    public Optional<OAuth2Client> findByClientId(String clientId) {
        return jpaRepository.findByClientId(clientId);
    }

    @Override
    public boolean existsByClientId(String clientId) {
        return jpaRepository.existsByClientId(clientId);
    }

    @Override
    public List<OAuth2Client> findAllByTenantIdOrderByCreatedAtDesc(UUID tenantId) {
        return jpaRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId);
    }

    @Override
    public Optional<OAuth2Client> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public <S extends OAuth2Client> S save(S client) {
        return jpaRepository.save(client);
    }

    @Override
    public void delete(OAuth2Client client) {
        jpaRepository.delete(client);
    }

    @Override
    public void deleteById(UUID id) {
        jpaRepository.deleteById(id);
    }
}
