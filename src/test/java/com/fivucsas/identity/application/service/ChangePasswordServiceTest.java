package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ChangePasswordCommand;
import com.fivucsas.identity.application.port.output.PasswordHistoryRepositoryPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.PasswordHistory;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChangePasswordServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordHistoryRepositoryPort passwordHistoryRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private com.fivucsas.identity.application.port.output.AuditLogPort auditLogPort;

    @InjectMocks
    private ChangePasswordService service;

    private final UUID userId = UUID.randomUUID();

    @Test
    void execute_WhenValidRequest_ShouldChangePassword() {
        // given
        User user = mock(User.class);
        when(user.getPasswordHash()).thenReturn("old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("currentPass1!", "old-hash")).thenReturn(true);
        when(passwordHistoryRepository.findRecentByUserId(eq(userId), any(PageRequest.class)))
                .thenReturn(Collections.emptyList());

        ChangePasswordCommand command = ChangePasswordCommand.builder()
                .userId(userId.toString())
                .currentPassword("currentPass1!")
                .newPassword("NewPassword1!")
                .build();

        // when
        service.execute(command);

        // then
        verify(passwordHistoryRepository).save(any(PasswordHistory.class));
        verify(user).updatePassword(eq("NewPassword1!"), eq(passwordEncoder));
        verify(userRepository).save(user);
    }

    @Test
    void execute_WhenUserNotFound_ShouldThrowException() {
        // given
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        ChangePasswordCommand command = ChangePasswordCommand.builder()
                .userId(userId.toString())
                .currentPassword("current")
                .newPassword("new")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void execute_WhenCurrentPasswordWrong_ShouldThrowInvalidCredentials() {
        // given
        User user = mock(User.class);
        when(user.getPasswordHash()).thenReturn("hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPassword", "hash")).thenReturn(false);

        ChangePasswordCommand command = ChangePasswordCommand.builder()
                .userId(userId.toString())
                .currentPassword("wrongPassword")
                .newPassword("NewPassword1!")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void execute_WhenNewPasswordMatchesHistory_ShouldThrowException() {
        // given
        User user = mock(User.class);
        when(user.getPasswordHash()).thenReturn("current-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("currentPass1!", "current-hash")).thenReturn(true);

        PasswordHistory historyEntry = mock(PasswordHistory.class);
        when(historyEntry.getPasswordHash()).thenReturn("old-hash-1");
        when(passwordHistoryRepository.findRecentByUserId(eq(userId), any(PageRequest.class)))
                .thenReturn(List.of(historyEntry));
        when(passwordEncoder.matches("NewPassword1!", "old-hash-1")).thenReturn(true);

        ChangePasswordCommand command = ChangePasswordCommand.builder()
                .userId(userId.toString())
                .currentPassword("currentPass1!")
                .newPassword("NewPassword1!")
                .build();

        // when/then
        assertThatThrownBy(() -> service.execute(command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not match");

        verify(userRepository, never()).save(any());
    }

    @Test
    void execute_ShouldSaveCurrentPasswordToHistoryBeforeChanging() {
        // given
        User user = mock(User.class);
        when(user.getPasswordHash()).thenReturn("current-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("currentPass1!", "current-hash")).thenReturn(true);
        when(passwordHistoryRepository.findRecentByUserId(eq(userId), any(PageRequest.class)))
                .thenReturn(Collections.emptyList());

        ChangePasswordCommand command = ChangePasswordCommand.builder()
                .userId(userId.toString())
                .currentPassword("currentPass1!")
                .newPassword("NewPassword1!")
                .build();

        // when
        service.execute(command);

        // then - verify history save happens
        verify(passwordHistoryRepository).save(argThat(ph ->
                ph.getUserId().equals(userId) && "current-hash".equals(ph.getPasswordHash())));
    }
}
