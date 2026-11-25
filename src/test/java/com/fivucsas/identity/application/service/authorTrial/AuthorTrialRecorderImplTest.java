package com.fivucsas.identity.application.service.authorTrial;

import com.fivucsas.identity.application.port.output.AuthorTrialStorePort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The recorder is inert while the trial surface is off (production default): no
 * query or write touches the V90 tables on any other tenant's hot MFA path. When
 * the surface is on it records the puzzle-session bookkeeping, and a store failure
 * is swallowed (recording must never change an authentication decision).
 */
@DisplayName("AuthorTrialRecorderImpl — off-surface inertness + best-effort writes")
class AuthorTrialRecorderImplTest {

    private static final UUID MFA_SESSION_ID =
            UUID.fromString("12121212-3434-5656-7878-909090909090");
    private static final UUID ATTEMPT_ID =
            UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    private final AuthorTrialStorePort store = mock(AuthorTrialStorePort.class);
    private final AuthorTrialAccessGuard guard = mock(AuthorTrialAccessGuard.class);
    private final AuthorTrialRecorderImpl recorder = new AuthorTrialRecorderImpl(store, guard);

    @Test
    void surfaceOff_TouchesNothing() {
        when(guard.surfaceEnabled()).thenReturn(false);

        recorder.trialSession(MFA_SESSION_ID);
        recorder.puzzleSessionCreated(ATTEMPT_ID, "session-1", "v2", "blink");
        recorder.challengeSubmitted("session-1", true, "ok");

        verifyNoInteractions(store);
    }

    @Test
    void surfaceOn_RecordsPuzzleSessionBookkeeping() {
        when(guard.surfaceEnabled()).thenReturn(true);

        recorder.puzzleSessionCreated(ATTEMPT_ID, "session-1", "v2", "blink");
        recorder.challengeSubmitted("session-1", true, "verified");
        recorder.challengeSubmitted("session-1", false, "trace_failed");

        verify(store).recordPuzzleSession(ATTEMPT_ID, "session-1", "v2", "blink");
        verify(store).recordChallengeSubmit("session-1", "pass", "verified");
        verify(store).recordChallengeSubmit("session-1", "fail", "trace_failed");
    }

    @Test
    void storeFailure_IsSwallowed() {
        when(guard.surfaceEnabled()).thenReturn(true);
        doThrow(new IllegalStateException("db down"))
                .when(store).recordChallengeSubmit(anyString(), anyString(), any());

        assertThatCode(() -> recorder.challengeSubmitted("session-1", true, "verified"))
                .doesNotThrowAnyException();
    }
}