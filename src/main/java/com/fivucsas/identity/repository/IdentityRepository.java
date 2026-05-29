package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Identity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * Spring Data repository for the platform-level {@link Identity} (person) entity
 * (Model A, Phase 1). Internal only — no controller/use-case surface in Phase 1;
 * Phase 2 adds the linking endpoints. Identities are cross-tenant by design, so
 * there is no tenant-scoped variant here.
 */
@Repository
public interface IdentityRepository extends JpaRepository<Identity, UUID> {
}
