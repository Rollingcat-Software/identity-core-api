package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.IdentityLinkUserPort;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter for {@link IdentityLinkUserPort} — the ONLY bridge
 * between Phase-2 account linking and the JPA {@code users} table.
 *
 * <p>Lives in {@code infrastructure..} (an {@code entity.User}-allowed package
 * per {@code UserDomainBoundaryTest}). It maps {@link User} rows into the
 * entity-free {@link MembershipView} projection so the application service
 * ({@code IdentityLinkService}) never imports the JPA entity.</p>
 *
 * <p>The {@code findMembershipsByIdentityId} read deliberately runs WITHOUT the
 * Hibernate tenant filter ({@link TenantFilterBypass}): an identity's
 * memberships span tenants by design (Model A), and they are the one person's
 * OWN rows — this is a platform-level read, not a cross-tenant browse of other
 * people. The lazy {@code tenant} proxy is force-initialized inside a try/catch
 * (same idiom as {@code EnrollmentQueryService}) so a soft-deleted tenant
 * renders a null name instead of throwing.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class IdentityLinkUserAdapter implements IdentityLinkUserPort {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TenantFilterBypass tenantFilterBypass;
    private final EntityManager entityManager;

    @Override
    @Transactional(readOnly = true)
    public Optional<MembershipView> findMembershipByEmail(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        // findByEmail already filters deleted_at via the JPQL; the global tenant
        // filter, if active, would scope to the active tenant — but an email is
        // globally unique, so bypass it to resolve the membership wherever it lives.
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findByEmail(email.trim()))
                .map(this::toView);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<MembershipView> findMembershipByUserId(UUID userId) {
        if (userId == null) {
            return Optional.empty();
        }
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findById(userId))
                .map(this::toView);
    }

    @Override
    @Transactional(readOnly = true)
    public List<MembershipView> findMembershipsByIdentityId(UUID identityId) {
        if (identityId == null) {
            return List.of();
        }
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findByIdentityId(identityId).stream()
                        .map(this::toView)
                        .toList());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean verifyPassword(UUID userId, String rawPassword) {
        if (userId == null || rawPassword == null || rawPassword.isEmpty()) {
            return false;
        }
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findById(userId)
                        .map(User::getPasswordHash)
                        .filter(hash -> hash != null && !hash.isBlank())
                        .map(hash -> passwordEncoder.matches(rawPassword, hash))
                        .orElse(false));
    }

    @Override
    @Transactional
    public void repointIdentity(UUID userId, UUID newIdentityId) {
        int rows = userRepository.updateIdentityId(userId, newIdentityId);
        if (rows != 1) {
            throw new IllegalStateException(
                    "Failed to re-point identity for user " + userId
                            + " (rows affected=" + rows + ")");
        }
        // The bulk UPDATE bypasses the persistence context; clear it so any
        // subsequent read in the same transaction sees the new FK rather than
        // a stale managed copy.
        entityManager.flush();
        entityManager.clear();
    }

    private MembershipView toView(User u) {
        String tenantName = null;
        UUID tenantId = null;
        try {
            Tenant tenant = u.getTenant();
            if (tenant != null) {
                tenantId = tenant.getId();
                tenantName = tenant.getName();
            }
        } catch (RuntimeException ex) {
            // Soft-deleted / missing tenant proxy — keep id from the raw FK if we
            // can, render a null name rather than aborting the whole list.
            log.debug("Could not initialize tenant for user {}: {}", u.getId(), ex.toString());
        }
        String role = u.getUserType() != null ? u.getUserType().name() : null;
        return new MembershipView(
                u.getId(),
                u.getIdentityId(),
                u.getEmail(),
                tenantId,
                tenantName,
                role,
                u.isActive());
    }
}
