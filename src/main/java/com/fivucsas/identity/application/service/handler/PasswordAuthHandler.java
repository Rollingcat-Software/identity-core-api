package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class PasswordAuthHandler implements AuthMethodHandler {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.PASSWORD;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String email = (String) data.get("email");
        String password = (String) data.get("password");

        if (email == null || password == null) {
            return StepResult.failure("Email and password are required");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            log.warn("Authentication failed: user not found for email: {}", email);
            return StepResult.failure("Invalid credentials");
        }

        if (!user.isActive()) {
            return StepResult.failure("Account is not active");
        }

        if (!user.checkPassword(password, passwordEncoder)) {
            log.warn("Authentication failed: invalid password for email: {}", email);
            return StepResult.failure("Invalid credentials");
        }

        log.info("Password authentication successful for user: {}", email);
        return StepResult.success(Map.of("userId", user.getId().toString(), "email", email));
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("email", "password");
    }
}
