package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideVoiceEmbeddingPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class VoiceVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final BiometricServicePort biometricService;
    // Audit H3 (GPU-less voice): gates the client-side-embedding path. Default
    // OFF means the legacy audio path below is byte-identical to before.
    private final ClientSideVoiceEmbeddingPolicy clientSideVoiceEmbeddingPolicy;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.VOICE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        // Cache user-id once to keep the entity.User boundary surface
        // (ArchUnit UserDomainBoundaryTest) at one call site per method —
        // matches FaceVerifyMfaStepHandler.
        java.util.UUID userId = user.getId();

        // ROUTING (audit H3): when the client-side-voice-embedding path is ON for
        // this tenant AND the payload carries a precomputed 256-d speaker
        // embedding (the raw audio never left the device), match against the bio
        // /voice/verify-embedding endpoint. Otherwise fall through to the
        // UNCHANGED legacy audio path. Default OFF (policy + no embedding) ⇒
        // identical to the prior behaviour. NOTE: an embedding carries no audio,
        // so the bio processor cannot run its replay/liveness check on it — an
        // embedding VOICE factor MUST be paired with a liveness factor in the
        // flow; this handler only routes the match.
        List<Double> embedding = extractEmbedding(data.get("embedding"));
        boolean embeddingPathEnabled =
                clientSideVoiceEmbeddingPolicy.isEnabledForTenant(session.getTenantId());
        if (embeddingPathEnabled && embedding != null && !embedding.isEmpty()) {
            String tenantId = session.getTenantId() != null ? session.getTenantId().toString() : null;
            Map<String, Object> embeddingResult =
                    biometricService.verifyVoiceEmbedding(tenantId, userId, embedding);
            return Boolean.TRUE.equals(embeddingResult.get("verified"))
                    ? MfaStepResult.ok()
                    : MfaStepResult.fail();
        }

        // --- Legacy audio path (UNCHANGED) ---
        String voiceData = (String) data.get("voiceData");
        if (voiceData == null || voiceData.isBlank()) {
            return MfaStepResult.fail();
        }
        Map<String, Object> result = biometricService.verifyVoice(userId, voiceData);
        return Boolean.TRUE.equals(result.get("verified"))
                ? MfaStepResult.ok()
                : MfaStepResult.fail();
    }

    /**
     * Coerces the {@code embedding} payload field (a JSON array deserialized into
     * a {@code List<?>} of {@link Number}, or absent) into a {@code List<Double>}.
     * Returns null when the value is absent or not a list; a non-numeric element
     * makes the whole embedding invalid (null) so a malformed payload falls back
     * to the legacy audio path rather than sending garbage to the bio service.
     * (Length validation to 256 is enforced bio-side, returning HTTP 422.)
     */
    private static List<Double> extractEmbedding(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return null;
        }
        if (list.isEmpty()) {
            return List.of();
        }
        List<Double> out = new ArrayList<>(list.size());
        for (Object el : list) {
            if (el instanceof Number n) {
                out.add(n.doubleValue());
            } else {
                return null; // malformed element → not a usable embedding
            }
        }
        return out;
    }
}
