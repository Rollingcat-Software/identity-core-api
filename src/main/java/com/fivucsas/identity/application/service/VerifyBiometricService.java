package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricNotEnrolledException;
import com.fivucsas.identity.domain.exception.BiometricVerificationException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

/**
 * Use case service for biometric verification.
 *
 * Implements the VerifyBiometricUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyBiometricService implements VerifyBiometricUseCase {

    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final BiometricServicePort biometricService;

    @Override
    @Transactional
    public BiometricResponse execute(VerifyBiometricCommand command) {
        log.info("Verifying biometric for user: {}", command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        if (!user.isBiometricEnrolled()) {
            throw new BiometricNotEnrolledException(command.getUserId());
        }

        // Call external biometric service
        Map<String, Object> response = biometricService.verifyFace(userId, command.getFaceImage());

        Boolean success = (Boolean) response.get("success");
        String message = (String) response.get("message");
        Double confidence = response.get("confidence") != null
            ? ((Number) response.get("confidence")).doubleValue()
            : null;

        if (!Boolean.TRUE.equals(success)) {
            throw new BiometricVerificationException("Face verification failed: " + message);
        }

        // Update verification count
        user.incrementVerificationCount();
        userRepository.save(user);

        log.info("Biometric verified successfully for user: {}", user.getId());

        return BiometricResponse.builder()
            .success(true)
            .message(message != null ? message : "Biometric verification successful")
            .confidence(confidence)
            .userId(command.getUserId())
            .build();
    }
}
