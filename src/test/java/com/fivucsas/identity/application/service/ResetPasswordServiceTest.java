package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ResetPasswordCommand;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.InvalidTokenException;
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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ResetPasswordServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoderPort passwordEncoder;
    @Mock private EmailServicePort emailServicePort;
    @Mock private AuditLogPort auditLogPort;

    @InjectMocks
    private ResetPasswordService service;

    @Test
    void execute_WhenValidToken_ShouldResetPasswordSuccessfully() {
        // given
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.getFullName()).thenReturn("Test User");
        when(user.isPasswordResetTokenExpired()).thenReturn(false);
        when(user.resetPassword(eq("valid-token"), anyString())).thenReturn(true);
        when(userRepository.findByPasswordResetToken("valid-token")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("NewPassword1!")).thenReturn("hashed-password");

        ResetPasswordCommand command = ResetPasswordCommand.builder()
                .token("valid-token")
                .newPassword("NewPassword1!")
                .ipAddress("127.0.0.1")
                .build();

        // when
        service.execute(command);

        // then
        verify(user).resetPassword("valid-token", "hashed-password");
        verify(user).resetFailedLoginAttempts();
        verify(userRepository).save(user);
        verify(emailServicePort).sendSecurityAlert(eq("user@test.com"), eq("Test User"), anyString());
        verify(auditLogPort).logSecurityEvent(
                eq(userId.toString()), eq("PASSWORD_RESET_SUCCESS"), eq("127.0.0.1"), anyString());
    }

    @Test
    void execute_WhenTokenNotFound_ShouldThrowInvalidTokenException() {
        // given
        when(userRepository.findByPasswordResetToken("invalid-token")).thenReturn(Optional.empty());

        ResetPasswordCommand command = ResetPasswordCommand.builder()
                .token("invalid-token")
                .newPassword("NewPassword1!")
                .ipAddress("127.0.0.1")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(InvalidTokenException.class);

        verify(auditLogPort).logSecurityEvent(eq("UNKNOWN"), eq("PASSWORD_RESET_FAILED"),
                eq("127.0.0.1"), anyString());
    }

    @Test
    void execute_WhenTokenExpired_ShouldThrowInvalidTokenException() {
        // given
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.isPasswordResetTokenExpired()).thenReturn(true);
        when(userRepository.findByPasswordResetToken("expired-token")).thenReturn(Optional.of(user));

        ResetPasswordCommand command = ResetPasswordCommand.builder()
                .token("expired-token")
                .newPassword("NewPassword1!")
                .ipAddress("127.0.0.1")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");

        verify(auditLogPort).logSecurityEvent(
                eq(userId.toString()), eq("PASSWORD_RESET_FAILED"), eq("127.0.0.1"), anyString());
    }

    @Test
    void execute_WhenResetPasswordReturnsFalse_ShouldThrowInvalidTokenException() {
        // given
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.isPasswordResetTokenExpired()).thenReturn(false);
        when(user.resetPassword(eq("token"), anyString())).thenReturn(false);
        when(userRepository.findByPasswordResetToken("token")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("NewPassword1!")).thenReturn("hashed");

        ResetPasswordCommand command = ResetPasswordCommand.builder()
                .token("token")
                .newPassword("NewPassword1!")
                .ipAddress("127.0.0.1")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Failed to reset password");
    }

    @Test
    void execute_WhenWeakPassword_ShouldThrowIllegalArgumentException() {
        // given
        User user = mock(User.class);
        when(user.isPasswordResetTokenExpired()).thenReturn(false);
        when(userRepository.findByPasswordResetToken("token")).thenReturn(Optional.of(user));

        ResetPasswordCommand command = ResetPasswordCommand.builder()
                .token("token")
                .newPassword("weak")  // too short, no uppercase, no digit, no special
                .ipAddress("127.0.0.1")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password does not meet policy");
    }
}
