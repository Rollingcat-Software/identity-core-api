package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class PasswordAuthHandlerTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private PasswordAuthHandler handler;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = mock(User.class);
        lenient().when(testUser.getId()).thenReturn(UUID.randomUUID());
        lenient().when(testUser.getEmail()).thenReturn("user@test.com");
        lenient().when(testUser.isActive()).thenReturn(true);
    }

    @Test
    void getMethodType_ShouldReturnPassword() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.PASSWORD);
    }

    @Test
    void validate_WhenValidCredentials_ShouldReturnSuccess() {
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(testUser));
        when(testUser.checkPassword("pass123", passwordEncoder)).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("email", "user@test.com", "password", "pass123"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsKey("userId");
    }

    @Test
    void validate_WhenMissingEmail_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of("password", "pass123"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Email and password are required");
    }

    @Test
    void validate_WhenUserNotFound_ShouldReturnFailure() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        StepResult result = handler.validate(session, step, Map.of("email", "unknown@test.com", "password", "pass123"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid credentials");
    }

    @Test
    void validate_WhenAccountInactive_ShouldReturnFailure() {
        when(testUser.isActive()).thenReturn(false);
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(testUser));

        StepResult result = handler.validate(session, step, Map.of("email", "user@test.com", "password", "pass123"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Account is not active");
    }

    @Test
    void validate_WhenWrongPassword_ShouldReturnFailure() {
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(testUser));
        when(testUser.checkPassword("wrong", passwordEncoder)).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("email", "user@test.com", "password", "wrong"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid credentials");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }

    @Test
    void requiredDataFields_ShouldReturnEmailAndPassword() {
        assertThat(handler.requiredDataFields()).containsExactlyInAnyOrder("email", "password");
    }
}
