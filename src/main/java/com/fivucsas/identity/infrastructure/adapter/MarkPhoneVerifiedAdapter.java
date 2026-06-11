package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.MarkPhoneVerifiedPort;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Infrastructure adapter for {@link MarkPhoneVerifiedPort} (F2, 2026-06-06).
 *
 * <p>Owns the {@code entity.User} mutation + persist so the application-layer
 * SMS_OTP login handlers can flip {@code phone_number_verified} without crossing
 * the {@code entity.User} hexagonal boundary (this package is on the
 * {@code UserDomainBoundaryTest} allow-list). Mirrors how
 * {@code AuthController.verifyPhone} sets the flag for the standalone
 * {@code POST /auth/verify-phone} endpoint: {@code user.verifyPhone()} +
 * {@code save}. Idempotent — skips the write when already verified or the id does
 * not resolve, so it never fails the login and never makes phone mandatory.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MarkPhoneVerifiedAdapter implements MarkPhoneVerifiedPort {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public void markPhoneVerified(UUID userId) {
        if (userId == null) {
            return;
        }
        User user = userRepository.findById(userId).orElse(null);
        if (user == null || user.isPhoneVerified()) {
            // Already verified (or unknown id) — nothing to do. Keeps the SMS_OTP
            // login path side-effect-free on repeat logins.
            return;
        }
        user.verifyPhone();
        userRepository.save(user);
        log.info("Phone marked verified via SMS_OTP login for user: {}", userId);
    }
}
