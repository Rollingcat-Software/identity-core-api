package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.service.transaction.TrackingTransactionManager;
import com.fivucsas.identity.application.service.transaction.TransactionRunner;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAccountStateGuardTest {

    @Mock private UserRepository userRepository;
    @Mock private AuditLogPort auditLogPort;

    private final TrackingTransactionManager transactionManager = new TrackingTransactionManager();
    private LoginAccountStateGuard guard;
    private User user;

    @BeforeEach
    void setUp() {
        guard = new LoginAccountStateGuard(userRepository, auditLogPort, new TransactionRunner(transactionManager));
        user = User.builder().id(UUID.randomUUID()).email("u@example.com")
                .firstName("A").lastName("B").status(UserStatus.ACTIVE).failedLoginAttempts(0).build();
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
    }

    @Test
    void recordFailedAttempt_WhenBelowThreshold_ShouldCommitTheStrikeThenAuditWithNoTransactionOpen() {
        List<Integer> openWhileAuditing = new ArrayList<>();
        doAnswer(invocation -> {
            openWhileAuditing.add(transactionManager.openTransactions());
            return null;
        }).when(auditLogPort).logAuthenticationFailed(any(), any(), any());

        boolean justLocked = guard.recordFailedAttempt(user.getId(), "u@example.com", "10.0.0.1");

        assertThat(justLocked).isFalse();
        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        assertThat(openWhileAuditing).containsExactly(0);
        assertThat(transactionManager.events()).containsExactly("begin", "commit");
        verify(auditLogPort).logAuthenticationFailed("u@example.com", "10.0.0.1",
                "Invalid credential (attempt 1/" + LoginAccountStateGuard.MAX_FAILED_ATTEMPTS + ")");
    }

    @Test
    void recordFailedAttempt_WhenThresholdReached_ShouldLockAndAuditTheLock() {
        for (int i = 1; i < LoginAccountStateGuard.MAX_FAILED_ATTEMPTS; i++) {
            user.incrementFailedLoginAttempts();
        }

        boolean justLocked = guard.recordFailedAttempt(user.getId(), "u@example.com", "10.0.0.1");

        assertThat(justLocked).isTrue();
        assertThat(user.isLocked()).isTrue();
        verify(auditLogPort).logAuthenticationFailed(eq("u@example.com"), eq("10.0.0.1"),
                eq("Account locked after " + LoginAccountStateGuard.MAX_FAILED_ATTEMPTS + " failed attempts"));
    }
}
