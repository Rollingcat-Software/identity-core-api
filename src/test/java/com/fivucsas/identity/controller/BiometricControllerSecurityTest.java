package com.fivucsas.identity.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Annotation-level authorization guard for the Phase-6 JSON client-embedding
 * enroll endpoint ({@code POST /api/v1/biometric/enroll-embedding/{userId}}).
 *
 * <p>The endpoint MUST be at least as protected as the multipart
 * {@code POST /api/v1/biometric/enroll/{userId}} ({@link BiometricController#enrollFace}):
 * the privacy-preserving JSON path enrolls the very same face template, so it
 * cannot relax the ownership/permission gate. This test pins the
 * {@code @PreAuthorize} expressions to be BYTE-IDENTICAL, so a future edit that
 * loosens the JSON endpoint (e.g. drops the {@code isCurrentUser} ownership
 * check, allowing a user to enroll an embedding for ANOTHER user's id) fails
 * here.
 *
 * <p>See {@link AuthFlowControllerSecurityTest} / {@link DeviceControllerSecurityTest}
 * for the rationale behind the reflective annotation-pin approach: the
 * {@code @WebMvcTest} controller slice uses {@code addFilters = false}, which
 * disables method security and so hides {@code @PreAuthorize} regressions.
 */
@DisplayName("BiometricController @PreAuthorize sweep (Phase-6 client-embedding enroll)")
class BiometricControllerSecurityTest {

    @Test
    @DisplayName("enrollFaceEmbedding (JSON) must carry the SAME @PreAuthorize as the multipart enrollFace")
    void jsonEnroll_isGuardedIdenticallyToMultipartEnroll() {
        Method json = findMethod("enrollFaceEmbedding");
        Method multipart = findMethod("enrollFace");

        PreAuthorize jsonAnn = json.getAnnotation(PreAuthorize.class);
        PreAuthorize multipartAnn = multipart.getAnnotation(PreAuthorize.class);

        assertThat(jsonAnn)
                .as("enrollFaceEmbedding must carry @PreAuthorize")
                .isNotNull();
        assertThat(multipartAnn)
                .as("enrollFace must carry @PreAuthorize (baseline)")
                .isNotNull();

        // Byte-identical: the JSON enroll path is NEITHER stricter nor looser than
        // the multipart image enroll — it gates on the same biometric:enroll
        // permission OR the caller being the subject user.
        assertThat(jsonAnn.value())
                .as("JSON enroll @PreAuthorize must equal the multipart enroll's, never loosened")
                .isEqualTo(multipartAnn.value());

        // Defense-in-depth assertions on the actual expression contents, so the
        // ownership check can never be silently dropped even if both drift together.
        assertThat(jsonAnn.value())
                .contains("hasAuthority('biometric:enroll')")
                .contains("@userSecurityService.isCurrentUser(#userId)")
                .contains(" or ");
    }

    @Test
    @DisplayName("enrollVoiceEmbedding (JSON) must carry the SAME @PreAuthorize as the audio enrollVoice")
    void jsonVoiceEnroll_isGuardedIdenticallyToAudioEnroll() {
        Method json = findMethod("enrollVoiceEmbedding");
        Method audio = findMethod("enrollVoice");

        PreAuthorize jsonAnn = json.getAnnotation(PreAuthorize.class);
        PreAuthorize audioAnn = audio.getAnnotation(PreAuthorize.class);

        assertThat(jsonAnn)
                .as("enrollVoiceEmbedding must carry @PreAuthorize")
                .isNotNull();
        assertThat(audioAnn)
                .as("enrollVoice must carry @PreAuthorize (baseline)")
                .isNotNull();

        // The client-embedding voice enroll is NEITHER stricter nor looser than the
        // audio enroll — same biometric:enroll permission OR subject-user ownership.
        assertThat(jsonAnn.value())
                .as("JSON voice enroll @PreAuthorize must equal the audio enroll's, never loosened")
                .isEqualTo(audioAnn.value());
        assertThat(jsonAnn.value())
                .contains("hasAuthority('biometric:enroll')")
                .contains("@userSecurityService.isCurrentUser(#userId)")
                .contains(" or ");
    }

    private static Method findMethod(String name) {
        for (Method m : BiometricController.class.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.isAnnotationPresent(PostMapping.class)) {
                return m;
            }
        }
        throw new AssertionError("Method " + name + " with @PostMapping not found on BiometricController");
    }
}
