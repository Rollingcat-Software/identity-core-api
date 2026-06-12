package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideVoiceEmbeddingPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Routing tests for {@link VoiceVerifyMfaStepHandler} across both
 * {@link ClientSideVoiceEmbeddingPolicy} states (audit H3, GPU-less voice).
 *
 * <ul>
 *   <li>policy OFF → always the legacy audio path ({@code verifyVoice}), even if
 *       an embedding is present (byte-identical legacy behaviour);</li>
 *   <li>policy ON + embedding present → the embedding path
 *       ({@code verifyVoiceEmbedding});</li>
 *   <li>policy ON but audio (no embedding) → still the legacy audio path.</li>
 * </ul>
 */
@DisplayName("VoiceVerifyMfaStepHandler — audio vs embedding routing")
class VoiceVerifyMfaStepHandlerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final String VOICE_DATA = "data:audio/wav;base64,ZmFrZS13YXY=";
    private static final List<Double> EMBEDDING = List.of(0.1, 0.2, 0.3);

    private BiometricServicePort bio;
    private MfaSession session;
    private User user;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        session = mock(MfaSession.class);
        user = mock(User.class);
        when(user.getId()).thenReturn(USER_ID);
        when(session.getTenantId()).thenReturn(TENANT_ID);
    }

    private VoiceVerifyMfaStepHandler handlerWithPolicy(boolean enabled) {
        ClientSideVoiceEmbeddingPolicy policy =
                new ClientSideVoiceEmbeddingPolicy(enabled, "");
        return new VoiceVerifyMfaStepHandler(bio, policy);
    }

    @Test
    @DisplayName("policy OFF + embedding present → legacy verifyVoice (audio), embedding ignored")
    void policyOff_embeddingPresent_usesAudioPath() {
        when(bio.verifyVoice(eq(USER_ID), eq(VOICE_DATA))).thenReturn(Map.of("verified", true));
        VoiceVerifyMfaStepHandler handler = handlerWithPolicy(false);

        Map<String, Object> data = Map.of("voiceData", VOICE_DATA, "embedding", EMBEDDING);
        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio, times(1)).verifyVoice(eq(USER_ID), eq(VOICE_DATA));
        verify(bio, never()).verifyVoiceEmbedding(any(), any(), any());
    }

    @Test
    @DisplayName("policy ON + embedding present → verifyVoiceEmbedding (embedding path)")
    void policyOn_embeddingPresent_usesEmbeddingPath() {
        when(bio.verifyVoiceEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), eq(EMBEDDING)))
                .thenReturn(Map.of("verified", true));
        VoiceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        // No "voiceData" key at all — the browser computed the embedding on-device.
        Map<String, Object> data = Map.of("embedding", EMBEDDING);
        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio, times(1)).verifyVoiceEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), eq(EMBEDDING));
        verify(bio, never()).verifyVoice(any(), any());
    }

    @Test
    @DisplayName("policy ON but audio only (no embedding) → legacy verifyVoice")
    void policyOn_audioOnly_usesAudioPath() {
        when(bio.verifyVoice(eq(USER_ID), eq(VOICE_DATA))).thenReturn(Map.of("verified", true));
        VoiceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        Map<String, Object> data = Map.of("voiceData", VOICE_DATA);
        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio, times(1)).verifyVoice(eq(USER_ID), eq(VOICE_DATA));
        verify(bio, never()).verifyVoiceEmbedding(any(), any(), any());
    }

    @Test
    @DisplayName("embedding path: server verified=false → fail")
    void policyOn_embeddingPath_serverRejects_fails() {
        when(bio.verifyVoiceEmbedding(any(), eq(USER_ID), any()))
                .thenReturn(Map.of("verified", false));
        VoiceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of("embedding", EMBEDDING));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("policy ON + neither audio nor embedding → fail, no bio call")
    void policyOn_noPayload_fails() {
        VoiceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of());

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("policy ON + empty embedding list + no audio → fail, no bio call")
    void policyOn_emptyEmbedding_fails() {
        VoiceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of("embedding", List.of()));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("supports() reports VOICE")
    void supportsVoice() {
        assertThat(handlerWithPolicy(false).supports().name()).isEqualTo("VOICE");
    }
}
