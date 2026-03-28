package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.OAuth2Client;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for OAuth2Client persistence operations.
 *
 * Follows Hexagonal Architecture: application defines the contract,
 * infrastructure provides the JPA implementation.
 */
public interface OAuth2ClientRepositoryPort {

    Optional<OAuth2Client> findByClientIdAndActiveTrue(String clientId);

    Optional<OAuth2Client> findByClientId(String clientId);

    boolean existsByClientId(String clientId);

    List<OAuth2Client> findAllByTenantIdOrderByCreatedAtDesc(UUID tenantId);

    Optional<OAuth2Client> findById(UUID id);

    <S extends OAuth2Client> S save(S client);

    void delete(OAuth2Client client);

    void deleteById(UUID id);
}
