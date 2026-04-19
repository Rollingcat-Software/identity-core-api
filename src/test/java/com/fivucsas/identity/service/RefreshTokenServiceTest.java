package com.fivucsas.identity.service;

import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RefreshTokenService} — focused on BE-M5 (2026-04-19):
 * createRefreshToken must NOT nuke every existing active token for the user.
 * That behavior broke legitimate multi-device sessions.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService")
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenService service;

    @Test
    @DisplayName("createRefreshToken does not revoke all existing user tokens [BE-M5]")
    void createRefreshToken_DoesNotRevokeAllUserTokens() {
        ReflectionTestUtils.setField(service, "refreshTokenDurationMs", 604_800_000L);

        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        service.createRefreshToken(user, "1.2.3.4", "JUnit");

        // BE-M5: the unconditional bulk-revoke was the broken behavior.
        verify(refreshTokenRepository, never()).revokeAllUserTokens(any(User.class), any());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }
}
