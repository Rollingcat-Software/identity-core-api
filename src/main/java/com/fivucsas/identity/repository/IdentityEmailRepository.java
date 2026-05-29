package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.IdentityEmail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data repository for {@link IdentityEmail} (Model A, Phase 1).
 *
 * <p>{@code findByEmailIgnoreCase} matches the case-insensitive global UNIQUE on
 * {@code lower(email)} (V66) — at most one row per address. Internal only in
 * Phase 1; Phase 2 adds the link/initiate + link/confirm flows that consume it.
 */
@Repository
public interface IdentityEmailRepository extends JpaRepository<IdentityEmail, UUID> {

    Optional<IdentityEmail> findByEmailIgnoreCase(String email);

    List<IdentityEmail> findByIdentityId(UUID identityId);
}
