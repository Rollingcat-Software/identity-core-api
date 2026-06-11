package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * F2 (2026-06-06): the adapter that owns the {@code entity.User} phone-verified
 * mutation. Idempotent — only writes when the user is found AND not already
 * verified, so SMS_OTP login can call it on every step without side effects.
 */
@ExtendWith(MockitoExtension.class)
class MarkPhoneVerifiedAdapterTest {

    @Mock private UserRepository userRepository;

    @InjectMocks
    private MarkPhoneVerifiedAdapter adapter;

    @Test
    void markPhoneVerified_WhenUnverifiedUser_ShouldVerifyAndSave() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.isPhoneVerified()).thenReturn(false);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        adapter.markPhoneVerified(userId);

        verify(user).verifyPhone();
        verify(userRepository).save(user);
    }

    @Test
    void markPhoneVerified_WhenAlreadyVerified_ShouldBeNoOp() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.isPhoneVerified()).thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        adapter.markPhoneVerified(userId);

        verify(user, never()).verifyPhone();
        verify(userRepository, never()).save(any());
    }

    @Test
    void markPhoneVerified_WhenUserNotFound_ShouldBeNoOp() {
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        adapter.markPhoneVerified(userId);

        verify(userRepository, never()).save(any());
    }

    @Test
    void markPhoneVerified_WhenNullId_ShouldBeNoOp() {
        adapter.markPhoneVerified(null);

        verifyNoInteractions(userRepository);
    }
}
