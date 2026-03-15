package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ChangePasswordCommand;
import com.fivucsas.identity.application.port.input.ChangePasswordUseCase;
import com.fivucsas.identity.application.port.output.PasswordHistoryRepositoryPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.PasswordHistory;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Use case service for changing a user's password.
 *
 * Encapsulates password change business logic: verifies current password,
 * checks history to prevent reuse, and persists the new password.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ChangePasswordService implements ChangePasswordUseCase {

    private static final int PASSWORD_HISTORY_LIMIT = 5;

    private final UserRepository userRepository;
    private final PasswordHistoryRepositoryPort passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void execute(ChangePasswordCommand command) {
        UUID uuid = UUID.fromString(command.getUserId());
        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        if (!passwordEncoder.matches(command.getCurrentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        // Check password history to prevent reuse
        List<PasswordHistory> recentPasswords = passwordHistoryRepository.findRecentByUserId(
                uuid, PageRequest.of(0, PASSWORD_HISTORY_LIMIT));
        for (PasswordHistory ph : recentPasswords) {
            if (passwordEncoder.matches(command.getNewPassword(), ph.getPasswordHash())) {
                throw new IllegalArgumentException(
                        "New password must not match any of the last " + PASSWORD_HISTORY_LIMIT + " passwords");
            }
        }

        // Save current password to history before changing
        passwordHistoryRepository.save(PasswordHistory.builder()
                .userId(uuid)
                .passwordHash(user.getPasswordHash())
                .build());

        user.updatePassword(command.getNewPassword(), passwordEncoder);
        userRepository.save(user);

        log.info("Password changed successfully for user: {}", uuid);
    }
}
