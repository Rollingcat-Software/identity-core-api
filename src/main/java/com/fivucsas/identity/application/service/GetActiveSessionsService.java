package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetActiveSessionsQuery;
import com.fivucsas.identity.application.dto.response.SessionResponse;
import com.fivucsas.identity.application.port.input.GetActiveSessionsUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.domain.repository.RefreshTokenRepository;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Use case service for getting active sessions.
 *
 * Implements the GetActiveSessionsUseCase input port.
 * Returns list of active refresh tokens as sessions.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GetActiveSessionsService implements GetActiveSessionsUseCase {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TenantFilterBypass tenantFilterBypass;

    @Override
    @Transactional(readOnly = true)
    public List<SessionResponse> execute(GetActiveSessionsQuery query) {
        log.info("Get active sessions request for user: {}", query.getEmail());

        // "My sessions" is user-centric — resolve the caller by their globally-unique
        // email WITHOUT the active-tenant filter. Otherwise a ROOT viewing their own
        // sessions while switched to another tenant (X-Tenant-ID) has their home-tenant
        // user row filtered out by @Filter(tenantFilter) → UserNotFoundException → 404.
        User user = tenantFilterBypass.runWithoutTenantFilter(() ->
            userRepository.findByEmail(query.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + query.getEmail())));

        List<RefreshToken> activeSessions = refreshTokenRepository.findActiveTokensByUser(user, Instant.now());

        log.info("Found {} active sessions for user: {}", activeSessions.size(), query.getEmail());

        return activeSessions.stream()
            .map(token -> mapToSessionResponse(token, query.getCurrentTokenId()))
            .collect(Collectors.toList());
    }

    private SessionResponse mapToSessionResponse(RefreshToken token, String currentTokenId) {
        String deviceInfo = SessionResponse.extractDeviceInfo(token.getUserAgent());

        return SessionResponse.builder()
            .sessionId(token.getId().toString())
            .ipAddress(token.getIpAddress())
            .userAgent(token.getUserAgent())
            .deviceInfo(deviceInfo)
            .createdAt(token.getCreatedAt())
            .expiryDate(token.getExpiryDate())
            .isCurrent(token.getId().toString().equals(currentTokenId))
            .build();
    }
}
