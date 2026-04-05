package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ForgotPasswordCommand;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ForgotPasswordServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private EmailServicePort emailServicePort;
    @Mock private AuditLogPort auditLogPort;

    @InjectMocks
    private ForgotPasswordService service;

    @Test
    void execute_WhenUserExists_ShouldSendResetEmail() {
        // given
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.getFullName()).thenReturn("Test User");
        when(user.generatePasswordResetToken()).thenReturn("reset-token-123");
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        ForgotPasswordCommand command = ForgotPasswordCommand.builder()
                .email("user@test.com")
                .ipAddress("127.0.0.1")
                .build();

        // when
        service.execute(command);

        // then
        verify(user).generatePasswordResetToken();
        verify(userRepository).save(user);
        verify(emailServicePort).sendPasswordResetEmail("user@test.com", "Test User", "reset-token-123");
        verify(auditLogPort).logSecurityEvent(
                eq(userId.toString()), eq("PASSWORD_RESET_REQUESTED"),
                eq("127.0.0.1"), anyString());
    }

    @Test
    void execute_WhenUserNotFound_ShouldThrowException() {
        // given
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        ForgotPasswordCommand command = ForgotPasswordCommand.builder()
                .email("unknown@test.com")
                .ipAddress("127.0.0.1")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining("unknown@test.com");

        verify(emailServicePort, never()).sendPasswordResetEmail(anyString(), anyString(), anyString());
    }

    @Test
    void execute_ShouldSaveUserAfterGeneratingToken() {
        // given
        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.randomUUID());
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.getFullName()).thenReturn("Test User");
        when(user.generatePasswordResetToken()).thenReturn("token");
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        ForgotPasswordCommand command = ForgotPasswordCommand.builder()
                .email("user@test.com")
                .ipAddress("10.0.0.1")
                .build();

        // when
        service.execute(command);

        // then
        verify(userRepository).save(user);
    }
}
