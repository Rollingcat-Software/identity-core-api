package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateApiKeyCommand;
import com.fivucsas.identity.application.dto.response.ApiKeyResponse;
import com.fivucsas.identity.application.port.input.CreateApiKeyUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.ApiKey;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

/**
 * Use case service for creating API keys.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CreateApiKeyService implements CreateApiKeyUseCase {

    private final UserRepository userRepository;
    private final ApiKeyRepository apiKeyRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogPort auditLogPort;

    private static final String KEY_PREFIX = "fiv_";
    private static final int KEY_LENGTH = 32;  // 32 bytes = 256 bits

    @Override
    @Transactional
    public ApiKeyResponse execute(CreateApiKeyCommand command) {
        log.info("Create API key request for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Generate secure random API key
        String apiKey = generateApiKey();
        String keyHash = passwordEncoder.encode(apiKey);
        String prefix = apiKey.substring(0, Math.min(12, apiKey.length()));

        // Set expiration (default: 1 year)
        Instant expiresAt = command.getExpiryDays() != null && command.getExpiryDays() > 0
            ? Instant.now().plus(command.getExpiryDays(), ChronoUnit.DAYS)
            : Instant.now().plus(365, ChronoUnit.DAYS);

        ApiKey newApiKey = ApiKey.builder()
            .user(user)
            .tenant(user.getTenant())
            .name(command.getName())
            .keyHash(keyHash)
            .prefix(prefix)
            .scopes(command.getScopes())
            .expiresAt(expiresAt)
            .isActive(true)
            .build();

        apiKeyRepository.save(newApiKey);

        log.info("API key created for user: {} with name: {}", command.getEmail(), command.getName());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "API_KEY_CREATED",
            command.getIpAddress(),
            "API key created: " + command.getName()
        );

        return ApiKeyResponse.builder()
            .id(newApiKey.getId().toString())
            .name(newApiKey.getName())
            .prefix(prefix)
            .fullKey(apiKey)  // Show ONLY on creation
            .scopes(newApiKey.getScopes())
            .expiresAt(newApiKey.getExpiresAt())
            .isActive(newApiKey.isActive())
            .createdAt(newApiKey.getCreatedAt())
            .message("IMPORTANT: Save this API key now. You won't be able to see it again!")
            .build();
    }

    private String generateApiKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[KEY_LENGTH];
        random.nextBytes(bytes);
        return KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
