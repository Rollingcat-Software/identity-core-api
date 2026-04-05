package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.mapper.UserResponseMapper;
import com.fivucsas.identity.application.port.input.GetCurrentUserUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for getting current authenticated user.
 *
 * Implements the GetCurrentUserUseCase input port.
 * Uses pure domain model (domain.model.user.User) via UserDomainRepository.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GetCurrentUserService implements GetCurrentUserUseCase {

    private final UserDomainRepository userRepository;
    private final TenantRepository tenantRepository;

    @Override
    @Transactional(readOnly = true)
    public UserResponse execute(GetUserByEmailQuery query) {
        log.info("Getting current user: {}", query.getEmail());

        User user = userRepository.findByEmail(query.getEmail())
            .orElseThrow(() -> new UserNotFoundException(query.getEmail()));

        // Resolve tenant name for the response
        String tenantName = null;
        if (user.getTenantId() != null) {
            tenantName = tenantRepository.findById(user.getTenantId())
                .map(com.fivucsas.identity.domain.model.tenant.Tenant::getName)
                .orElse(null);
        }

        return UserResponseMapper.fromDomain(user, tenantName);
    }
}
