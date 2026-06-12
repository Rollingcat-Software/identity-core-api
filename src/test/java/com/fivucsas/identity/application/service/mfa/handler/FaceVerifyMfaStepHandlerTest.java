package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;

/**
 * Routing tests for {@link FaceVerifyMfaStepHandler} across both
 * {@link ClientSideEmbeddingPolicy} states (Phase 5, sub-project A).
 *
 * <ul>
 *   <li>policy OFF → always the legacy image path ({@code verifyFace}), even if
 *       an embedding is present (byte-identical legacy behaviour);</li>
 *   <li>policy ON + embedding present → the embedding path
 *       ({@code verifyEmbedding});</li>
 *   <li>policy ON but image (no embedding) → still the legacy image path.</li>
 * </ul>
 * The {@code verified}/spoof handling is shared by both paths.
 */
@DisplayName("FaceVerifyMfaStepHandler — image vs embedding routing")
class FaceVerifyMfaStepHandlerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final String IMAGE_B64 = Base64.getEncoder().encodeToString("fake-jpeg".getBytes());
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

    private FaceVerifyMfaStepHandler handlerWithPolicy(boolean enabled) {
        ClientSideEmbeddingPolicy policy =
                new ClientSideEmbeddingPolicy(enabled, "");
        return new FaceVerifyMfaStepHandler(bio, policy);
    }

    @Test
    @DisplayName("policy OFF + embedding present → legacy verifyFace (image), embedding ignored")
    void policyOff_embeddingPresent_usesImagePath() {
        when(bio.verifyFace(eq(USER_ID), any())).thenReturn(Map.of("verified", true));
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(false);

        Map<String, Object> data = Map.of("image", IMAGE_B64, "embedding", EMBEDDING);
        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio, times(1)).verifyFace(eq(USER_ID), any());
        verify(bio, never()).verifyEmbedding(any(), any(), any());
    }

    @Test
    @DisplayName("policy ON + embedding present → verifyEmbedding (embedding path)")
    void policyOn_embeddingPresent_usesEmbeddingPath() {
        when(bio.verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), eq(EMBEDDING)))
                .thenReturn(Map.of("verified", true));
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        // No "image" key at all — the browser computed the embedding on-device.
        Map<String, Object> data = Map.of("embedding", EMBEDDING);
        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio, times(1)).verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), eq(EMBEDDING));
        verify(bio, never()).verifyFace(any(), any());
    }

    @Test
    @DisplayName("policy ON but image only (no embedding) → legacy verifyFace")
    void policyOn_imageOnly_usesImagePath() {
        when(bio.verifyFace(eq(USER_ID), any())).thenReturn(Map.of("verified", true));
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        Map<String, Object> data = Map.of("image", IMAGE_B64);
        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio, times(1)).verifyFace(eq(USER_ID), any());
        verify(bio, never()).verifyEmbedding(any(), any(), any());
    }

    @Test
    @DisplayName("embedding path: server verified=false → fail")
    void policyOn_embeddingPath_serverRejects_fails() {
        when(bio.verifyEmbedding(any(), eq(USER_ID), any()))
                .thenReturn(Map.of("verified", false));
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of("embedding", EMBEDDING));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("embedding path: SPOOF_DETECTED error_code → hard fail")
    void policyOn_embeddingPath_spoof_fails() {
        when(bio.verifyEmbedding(any(), eq(USER_ID), any()))
                .thenReturn(Map.of("error_code", "SPOOF_DETECTED"));
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of("embedding", EMBEDDING));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("embedding path: missing `verified` field → hard reject (fail-closed)")
    void policyOn_embeddingPath_missingVerified_failsClosed() {
        when(bio.verifyEmbedding(any(), eq(USER_ID), any()))
                .thenReturn(Map.of("distance", 0.3));
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of("embedding", EMBEDDING));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("policy ON + neither image nor embedding → fail, no bio call")
    void policyOn_noPayload_fails() {
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of());

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("policy ON + empty embedding list + no image → fail, no bio call")
    void policyOn_emptyEmbedding_fails() {
        FaceVerifyMfaStepHandler handler = handlerWithPolicy(true);

        MfaStepResult result = handler.verify(session, user, Map.of("embedding", List.of()));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }
}
