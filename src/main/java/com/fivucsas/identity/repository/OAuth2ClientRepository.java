package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for OAuth2Client entities.
 */
@Repository
public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, UUID> {

    Optional<OAuth2Client> findByClientId(String clientId);

    Optional<OAuth2Client> findByClientIdAndActiveTrue(String clientId);

    boolean existsByClientId(String clientId);
}
