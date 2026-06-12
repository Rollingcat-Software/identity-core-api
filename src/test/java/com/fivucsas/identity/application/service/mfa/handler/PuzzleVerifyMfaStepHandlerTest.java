package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Server-authoritative VERDICT tests for {@link PuzzleVerifyMfaStepHandler}
 * (CV-2 of the puzzle-as-login convergence).
 *
 * <p>The crux: the client sends ONLY an opaque {@code puzzle_session_id}; the
 * handler asks the biometric-processor for the AUTHORITATIVE verdict (passing the
 * SERVER's user_id + tenant_id from the MFA session, never any client value) and
 * passes ONLY on {@code verified:true}. It is FAIL-CLOSED on a missing field,
 * a fail-closed adapter error map (404/non-2xx/transport), a {@code verified:false},
 * a missing server tenant, or any error/timeout — mirroring
 * {@link FaceVerifyMfaStepHandler}.
 */
@DisplayName("PuzzleVerifyMfaStepHandler — server-authoritative session verdict")
class PuzzleVerifyMfaStepHandlerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final String SESSION_ID = "tok_opaque_server_issued_123";

    private BiometricServicePort bio;
    private MfaSession session;
    private User user;
    private PuzzleVerifyMfaStepHandler handler;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        session = mock(MfaSession.class);
        user = mock(User.class);
        lenient().when(user.getId()).thenReturn(USER_ID);
        lenient().when(session.getUserId()).thenReturn(USER_ID);
        lenient().when(session.getTenantId()).thenReturn(TENANT_ID);
        handler = new PuzzleVerifyMfaStepHandler(bio);
    }

    @Test
    @DisplayName("supports() → PUZZLE")
    void supportsPuzzle() {
        assertThat(handler.supports()).isEqualTo(AuthMethodType.PUZZLE);
    }

    // ---- helpers -----------------------------------------------------------

    private Map<String, Object> dataWithSessionId(Object sessionId) {
        Map<String, Object> data = new HashMap<>();
        data.put("puzzle_session_id", sessionId);
        return data;
    }

    private void bioVerdict(boolean verified) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("verified", verified);
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class))).thenReturn(resp);
    }

    // ---- happy path --------------------------------------------------------

    @Test
    @DisplayName("bio verdict verified:true → success")
    void verdictTrue_success() {
        bioVerdict(true);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
    }

    // ---- the "server-stamped identity" proof -------------------------------

    @Test
    @DisplayName("verdict uses the SERVER user_id/tenant_id, NOT any client-supplied identity")
    void verdictUsesServerIdentity_notClientValue() {
        bioVerdict(true);

        // Client tries to smuggle a foreign owner identity in the payload.
        Map<String, Object> data = dataWithSessionId(SESSION_ID);
        data.put("user_id", UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd").toString());
        data.put("tenant_id", UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").toString());

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();

        // The verdict MUST carry the SERVER MFA-session identity, never the client's.
        ArgumentCaptor<UUID> userCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<UUID> tenantCaptor = ArgumentCaptor.forClass(UUID.class);
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), userCaptor.capture(), tenantCaptor.capture());
        assertThat(userCaptor.getValue()).isEqualTo(USER_ID);
        assertThat(tenantCaptor.getValue()).isEqualTo(TENANT_ID);
    }

    @Test
    @DisplayName("client says passed/verified but bio→verified:false → FAIL (no client trust)")
    void clientClaimsPassed_butBioRejects_fails() {
        bioVerdict(false);

        Map<String, Object> data = dataWithSessionId(SESSION_ID);
        data.put("passed", true);   // forged client claim
        data.put("verified", true); // forged client claim

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isFalse();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
    }

    // ---- hard-fail: bio verdict defects ------------------------------------

    @Test
    @DisplayName("bio verdict verified:false → fail")
    void verdictFalse_fails() {
        bioVerdict(false);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio verdict missing `verified` field → hard fail (fail-closed)")
    void missingVerifiedField_failsClosed() {
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class)))
                .thenReturn(Map.of("foo", "bar"));

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("adapter fail-closed error map (404/non-2xx/transport: success=false, no `verified`) → hard fail")
    void adapterErrorMap_failsClosed() {
        // The adapter returns {success:false, message:...} (with NO `verified` key)
        // on a bio 404 (unknown/expired/consumed), other non-2xx, or transport error.
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class)))
                .thenReturn(Map.of("success", false, "message", "Puzzle session verdict rejected: 404"));

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio verdict null → hard fail")
    void nullVerdict_failsClosed() {
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class))).thenReturn(null);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio throws (error/timeout) → hard fail, no fail-open")
    void bioError_failsClosed() {
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class)))
                .thenThrow(new RuntimeException("bio unreachable / timeout"));

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    // ---- malformed / missing payload ---------------------------------------

    @Test
    @DisplayName("no puzzle_session_id in payload → fail, no bio call")
    void noSessionId_fails() {
        MfaStepResult result = handler.verify(session, user, Map.of());

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("blank puzzle_session_id → fail, no bio call")
    void blankSessionId_fails() {
        MfaStepResult result = handler.verify(session, user, dataWithSessionId("   "));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("camelCase puzzleSessionId is also accepted → success")
    void camelCaseSessionId_accepted() {
        bioVerdict(true);
        Map<String, Object> data = new HashMap<>();
        data.put("puzzleSessionId", SESSION_ID);

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
    }

    @Test
    @DisplayName("MFA session carries no tenant → fail-closed, no bio call (cannot owner-bind)")
    void noServerTenant_failsClosed() {
        when(session.getTenantId()).thenReturn(null);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }
}
