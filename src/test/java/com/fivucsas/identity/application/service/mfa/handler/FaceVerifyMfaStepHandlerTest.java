package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.FaceEmbeddingLivenessPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Routing tests for {@link FaceVerifyMfaStepHandler} across both
 * {@link ClientSideEmbeddingPolicy} states (Phase 5, sub-project A), plus the
 * gap Ü2 liveness rule ({@link FaceEmbeddingLivenessPolicy}).
 *
 * <ul>
 *   <li>policy OFF → always the legacy image path ({@code verifyFace}), even if
 *       an embedding is present (byte-identical legacy behaviour);</li>
 *   <li>policy ON + embedding present → the embedding path
 *       ({@code verifyEmbedding}), subject to the Ü2 rule when no PUZZLE was
 *       completed earlier;</li>
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
    private AuditLogPort audit;
    private MfaSession session;
    private User user;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        audit = mock(AuditLogPort.class);
        session = mock(MfaSession.class);
        user = mock(User.class);
        when(user.getId()).thenReturn(USER_ID);
        when(session.getTenantId()).thenReturn(TENANT_ID);
    }

    private FaceVerifyMfaStepHandler handlerWithPolicy(boolean enabled) {
        // Default liveness mode (AUDIT): the routing contract below must be
        // unchanged by the Ü2 rule.
        return handler(enabled, "AUDIT");
    }

    private FaceVerifyMfaStepHandler handler(boolean embeddingEnabled, String livenessMode) {
        ClientSideEmbeddingPolicy policy =
                new ClientSideEmbeddingPolicy(embeddingEnabled, "");
        return new FaceVerifyMfaStepHandler(bio, policy,
                new FaceEmbeddingLivenessPolicy(livenessMode, ""), audit);
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

    // ─────────────────────────────────────────────────────────────────
    // Gap Ü2: liveness rule for the embedding path
    // (FaceEmbeddingLivenessPolicy: OFF | AUDIT | ENFORCE × paired × image)
    // ─────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Ü2 liveness rule")
    class LivenessRule {

        @BeforeEach
        void stubSession() {
            when(session.getCurrentStep()).thenReturn(2);
            when(session.getTotalSteps()).thenReturn(2);
            when(session.getUserAgent()).thenReturn("ua/1.0");
            when(session.getIpAddress()).thenReturn("10.0.0.9");
        }

        private void unpaired() {
            when(session.getCompletedMethods()).thenReturn(List.of("PASSWORD"));
        }

        private void paired() {
            when(session.getCompletedMethods()).thenReturn(List.of("PASSWORD", "PUZZLE"));
        }

        private void embeddingMatches() {
            when(bio.verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), eq(EMBEDDING)))
                    .thenReturn(Map.of("verified", true));
        }

        private void imageMatches() {
            when(bio.verifyFace(eq(USER_ID), any())).thenReturn(Map.of("verified", true));
        }

        // ---- OFF ----

        @Test
        @DisplayName("OFF + unpaired + no image → embedding path, no audit")
        void off_unpaired_noImage() {
            unpaired();
            embeddingMatches();

            MfaStepResult r = handler(true, "OFF").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.valid()).isTrue();
            assertThat(r.isChallenge()).isFalse();
            verify(bio, never()).verifyFace(any(), any());
            verifyNoInteractions(audit);
        }

        @Test
        @DisplayName("OFF + unpaired + image present → embedding still wins (old behaviour), no audit")
        void off_unpaired_image() {
            unpaired();
            embeddingMatches();

            MfaStepResult r = handler(true, "OFF").verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            verify(bio, never()).verifyFace(any(), any());
            verifyNoInteractions(audit);
        }

        @Test
        @DisplayName("OFF + paired → embedding path, no audit")
        void off_paired() {
            paired();
            embeddingMatches();

            MfaStepResult r = handler(true, "OFF").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.valid()).isTrue();
            verifyNoInteractions(audit);
        }

        // ---- AUDIT ----

        @Test
        @DisplayName("AUDIT + unpaired + no image → embedding path + FACE_EMBEDDING_UNPAIRED audit (no embedding in it)")
        void audit_unpaired_noImage() {
            unpaired();
            embeddingMatches();

            MfaStepResult r = handler(true, "AUDIT").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.valid()).isTrue();
            assertThat(r.isChallenge()).isFalse();
            verify(bio, never()).verifyFace(any(), any());
            verify(audit).logSecurityEvent(eq(USER_ID.toString()), eq("FACE_EMBEDDING_UNPAIRED"),
                    eq("10.0.0.9"), contains("userAgent=ua/1.0"));
            verify(audit).logSecurityEvent(any(), any(), any(), contains("tenantId=" + TENANT_ID));
            verify(audit).logSecurityEvent(any(), any(), any(), contains("step=2/2"));
            verify(audit, never()).logSecurityEvent(any(), any(), any(), contains("0.1"));
        }

        @Test
        @DisplayName("AUDIT + unpaired + image present → embedding still wins (unchanged) + audit")
        void audit_unpaired_image() {
            unpaired();
            embeddingMatches();

            MfaStepResult r = handler(true, "AUDIT").verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            verify(bio, never()).verifyFace(any(), any());
            verify(audit).logSecurityEvent(any(), eq("FACE_EMBEDDING_UNPAIRED"), any(), anyString());
        }

        @Test
        @DisplayName("AUDIT + paired → embedding path, no audit")
        void audit_paired() {
            paired();
            embeddingMatches();

            MfaStepResult r = handler(true, "AUDIT").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.valid()).isTrue();
            verifyNoInteractions(audit);
        }

        @Test
        @DisplayName("AUDIT: a failing audit write never changes the login outcome")
        void audit_failureIsSwallowed() {
            unpaired();
            embeddingMatches();
            doThrow(new RuntimeException("db down"))
                    .when(audit).logSecurityEvent(any(), any(), any(), any());

            MfaStepResult r = handler(true, "AUDIT").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.valid()).isTrue();
        }

        // ---- ENFORCE ----

        @Test
        @DisplayName("ENFORCE + unpaired + no image → FACE_IMAGE_REQUIRED challenge, verifyEmbedding never called")
        void enforce_unpaired_noImage_challenge() {
            unpaired();

            MfaStepResult r = handler(true, "ENFORCE").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.isChallenge()).isTrue();
            assertThat(r.valid()).isFalse();
            assertThat(r.challengeResponse())
                    .containsEntry("status", "FACE_IMAGE_REQUIRED")
                    .containsEntry("method", "FACE")
                    .containsEntry("requiredInput", "image")
                    .containsEntry("currentStep", 2)
                    .containsEntry("totalSteps", 2)
                    .containsEntry("message", "Face verification requires an image capture");
            verifyNoInteractions(bio);
            verify(audit).logSecurityEvent(eq(USER_ID.toString()), eq("FACE_IMAGE_REQUIRED"),
                    eq("10.0.0.9"), anyString());
        }

        @Test
        @DisplayName("ENFORCE + unpaired + image present → verifyFace (PAD), verifyEmbedding never called")
        void enforce_unpaired_image_reroutes() {
            unpaired();
            imageMatches();

            MfaStepResult r = handler(true, "ENFORCE").verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            assertThat(r.isChallenge()).isFalse();
            verify(bio, times(1)).verifyFace(eq(USER_ID), any());
            verify(bio, never()).verifyEmbedding(any(), any(), any());
            verify(audit).logSecurityEvent(eq(USER_ID.toString()), eq("FACE_EMBEDDING_REROUTED_TO_IMAGE"),
                    any(), anyString());
        }

        @Test
        @DisplayName("ENFORCE + unpaired + image re-routed: SPOOF_DETECTED still hard-fails")
        void enforce_reroute_spoofFails() {
            unpaired();
            when(bio.verifyFace(eq(USER_ID), any()))
                    .thenReturn(Map.of("error_code", "SPOOF_DETECTED", "verified", true));

            MfaStepResult r = handler(true, "ENFORCE").verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", IMAGE_B64));

            assertThat(r.valid()).isFalse();
            assertThat(r.isChallenge()).isFalse();
        }

        @Test
        @DisplayName("ENFORCE + unpaired + blank image → treated as no image → challenge")
        void enforce_unpaired_blankImage_challenge() {
            unpaired();

            MfaStepResult r = handler(true, "ENFORCE").verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", "  "));

            assertThat(r.isChallenge()).isTrue();
            verifyNoInteractions(bio);
        }

        @Test
        @DisplayName("ENFORCE + paired (PUZZLE earlier) → embedding path, no audit")
        void enforce_paired_embedding() {
            paired();
            embeddingMatches();

            MfaStepResult r = handler(true, "ENFORCE").verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.valid()).isTrue();
            verify(bio, never()).verifyFace(any(), any());
            verifyNoInteractions(audit);
        }

        @Test
        @DisplayName("ENFORCE + paired + image present → embedding path (pairing satisfied)")
        void enforce_paired_image_embeddingWins() {
            paired();
            embeddingMatches();

            MfaStepResult r = handler(true, "ENFORCE").verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            verify(bio, never()).verifyFace(any(), any());
        }

        @Test
        @DisplayName("ENFORCE via the canary list for this tenant while the global mode is AUDIT → challenge")
        void enforce_viaCanary() {
            unpaired();
            FaceVerifyMfaStepHandler h = new FaceVerifyMfaStepHandler(bio,
                    new ClientSideEmbeddingPolicy(true, ""),
                    new FaceEmbeddingLivenessPolicy("AUDIT", TENANT_ID.toString()), audit);

            MfaStepResult r = h.verify(session, user, Map.of("embedding", EMBEDDING));

            assertThat(r.isChallenge()).isTrue();
            verifyNoInteractions(bio);
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFF", "AUDIT", "ENFORCE"})
        @DisplayName("image-only payload → identical image path in every mode, no audit")
        void imagePath_identicalInEveryMode(String mode) {
            imageMatches();

            MfaStepResult r = handler(true, mode).verify(session, user, Map.of("image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            verify(bio, times(1)).verifyFace(eq(USER_ID), any());
            verify(bio, never()).verifyEmbedding(any(), any(), any());
            verifyNoInteractions(audit);
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFF", "AUDIT", "ENFORCE"})
        @DisplayName("image path: SPOOF_DETECTED hard-fails in every mode")
        void imagePath_spoofFailsInEveryMode(String mode) {
            when(bio.verifyFace(eq(USER_ID), any()))
                    .thenReturn(Map.of("error_code", "SPOOF_DETECTED", "verified", true));

            MfaStepResult r = handler(true, mode).verify(session, user, Map.of("image", IMAGE_B64));

            assertThat(r.valid()).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFF", "AUDIT", "ENFORCE"})
        @DisplayName("malformed embedding → falls through to the image path in every mode, no audit")
        void malformedEmbedding_fallsThrough(String mode) {
            imageMatches();

            MfaStepResult r = handler(true, mode).verify(session, user,
                    Map.of("embedding", List.of(0.1, "x", 0.3), "image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            verify(bio, times(1)).verifyFace(eq(USER_ID), any());
            verify(bio, never()).verifyEmbedding(any(), any(), any());
            verifyNoInteractions(audit);
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFF", "AUDIT", "ENFORCE"})
        @DisplayName("embedding path OFF (ClientSideEmbeddingPolicy) → liveness rule never applied")
        void embeddingPathOff_ruleNotApplied(String mode) {
            imageMatches();

            MfaStepResult r = handler(false, mode).verify(session, user,
                    Map.of("embedding", EMBEDDING, "image", IMAGE_B64));

            assertThat(r.valid()).isTrue();
            assertThat(r.isChallenge()).isFalse();
            verifyNoInteractions(audit);
        }
    }
}
