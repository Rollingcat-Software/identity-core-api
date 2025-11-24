package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricEnrollmentException;
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
 * Use case service for biometric enrollment.
 *
 * Implements the EnrollBiometricUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EnrollBiometricService implements EnrollBiometricUseCase {

    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final BiometricServicePort biometricService;

    @Override
    @Transactional
    public BiometricResponse execute(EnrollBiometricCommand command) {
        log.info("Enrolling biometric for user: {}", command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // Call external biometric service
        Map<String, Object> response = biometricService.enrollFace(userId, command.getFaceImage());

        Boolean success = (Boolean) response.get("success");
        String message = (String) response.get("message");

        if (!Boolean.TRUE.equals(success)) {
            throw new BiometricEnrollmentException("Face enrollment failed: " + message);
        }

        // Update user enrollment status
        user.enrollBiometric();
        userRepository.save(user);

        log.info("Biometric enrolled successfully for user: {}", user.getId());

        return BiometricResponse.builder()
            .success(true)
            .message(message != null ? message : "Biometric enrollment successful")
            .userId(command.getUserId())
            .build();
    }
}
