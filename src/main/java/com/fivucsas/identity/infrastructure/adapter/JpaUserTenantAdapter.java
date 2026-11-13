package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.UserTenantPort;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * {@link UserTenantPort} over JPA: reads the user with the Hibernate {@code tenantFilter}
 * disabled, so the verdict comes from the row itself and not from the request's tenant.
 */
@Component
@RequiredArgsConstructor
public class JpaUserTenantAdapter implements UserTenantPort {

    private final UserRepository userRepository;
    private final TenantFilterBypass tenantFilterBypass;

    @Override
    public Optional<UUID> findTenantIdOfUser(UUID userId) {
        if (userId == null) {
            return Optional.empty();
        }
        return tenantFilterBypass.runWithoutTenantFilter(() -> userRepository.findById(userId))
                .map(User::getTenant)
                .map(Tenant::getId);
    }
}
