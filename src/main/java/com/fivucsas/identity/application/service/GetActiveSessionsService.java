package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetActiveSessionsQuery;
import com.fivucsas.identity.application.dto.response.SessionResponse;
import com.fivucsas.identity.application.port.input.GetActiveSessionsUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.RefreshTokenRepository;
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

    @Override
    @Transactional(readOnly = true)
    public List<SessionResponse> execute(GetActiveSessionsQuery query) {
        log.info("Get active sessions request for user: {}", query.getEmail());

        User user = userRepository.findByEmail(query.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + query.getEmail()));

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
