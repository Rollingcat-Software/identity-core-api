package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class FaceVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final BiometricServicePort biometricService;
    // Phase 5 (sub-project A): gates the client-side-embedding path. Default OFF
    // means the legacy image path below is byte-identical to before.
    private final ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.FACE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        // Cache user-id once to keep the entity.User boundary surface
        // (ArchUnit UserDomainBoundaryTest) at one call site per method —
        // matches the pattern in FaceAuthHandler.
        java.util.UUID userId = user.getId();

        // ROUTING (Phase 5, sub-project A): when the client-side-embedding path is
        // ON for this tenant AND the payload carries a precomputed embedding (512
        // floats — the raw image never left the device), match against the bio
        // /verify-embedding endpoint. Otherwise fall through to the UNCHANGED
        // legacy image path. Default OFF (policy + no embedding) ⇒ identical to
        // the pre-Phase-5 behaviour. NOTE: an embedding carries no frame, so the
        // bio processor cannot run liveness/anti-spoof on it — an embedding FACE
        // factor MUST be paired with a liveness factor (puzzle/passive) in the
        // flow (enforced by sub-projects B/C); this handler only routes the match.
        List<Double> embedding = extractEmbedding(data.get("embedding"));
        boolean embeddingPathEnabled =
                clientSideEmbeddingPolicy.isEnabledForTenant(session.getTenantId());
        if (embeddingPathEnabled && embedding != null && !embedding.isEmpty()) {
            String tenantId = session.getTenantId() != null ? session.getTenantId().toString() : null;
            Map<String, Object> embeddingResult =
                    biometricService.verifyEmbedding(tenantId, userId, embedding);
            return interpretFaceResult(userId, embeddingResult, "embedding");
        }

        // --- Legacy image path (UNCHANGED) ---
        String image = (String) data.get("image");
        if (image == null || image.isBlank()) {
            return MfaStepResult.fail();
        }
        byte[] bytes = Base64.getDecoder().decode(
                image.contains(",") ? image.substring(image.indexOf(",") + 1) : image);
        MultipartFile faceFile = new InMemoryFaceImage(bytes);

        Map<String, Object> faceResult = biometricService.verifyFace(userId, faceFile);
        return interpretFaceResult(userId, faceResult, "image");
    }

    /**
     * Shared verdict interpreter for both the image and embedding paths. Applies
     * the exact same security rules to the bio response map:
     * <ol>
     *   <li>hard-fail on {@code error_code == SPOOF_DETECTED};</li>
     *   <li>trust ONLY the bio processor's {@code verified} field (no client/
     *       handler-side confidence fallback — fail-open vector, see
     *       INVESTIGATION_FAILOPEN_2026-05-07.md F3 / BACKEND_REVIEW 2026-05-12 P0);</li>
     *   <li>missing/null {@code verified} ⇒ hard reject, logged loudly.</li>
     * </ol>
     */
    private MfaStepResult interpretFaceResult(java.util.UUID userId,
                                              Map<String, Object> faceResult,
                                              String pathLabel) {
        // Anti-spoof: hard-fail if biometric-processor flagged the frame.
        Object errorCode = faceResult.get("error_code");
        if (errorCode instanceof String ec && "SPOOF_DETECTED".equals(ec)) {
            log.warn("AUDIT: MFA face spoof detected ({} path) — userId={}", pathLabel, userId);
            return MfaStepResult.fail();
        }

        // SECURITY (P0, BACKEND_REVIEW 2026-05-12): Trust ONLY the bio
        // processor's `verified` field. The bio processor applies the adaptive
        // aging threshold (VERIFICATION_THRESHOLD_AGED_*) server-side; a
        // handler-side confidence fallback silently overrides that policy and is
        // a fail-open vector. If `verified` is missing/null, treat it as a hard
        // reject and log loudly.
        Object verifiedClaim = faceResult.get("verified");
        if (verifiedClaim == null) {
            log.error("AUDIT: MFA face verify missing `verified` field ({} path) — userId={}, rejecting. response keys={}",
                    pathLabel, userId, faceResult.keySet());
            return MfaStepResult.fail();
        }
        boolean verified = Boolean.TRUE.equals(verifiedClaim)
                || "true".equalsIgnoreCase(String.valueOf(verifiedClaim));
        if (!verified) {
            log.warn("AUDIT: MFA face verify failed ({} path, server verified=false) — userId={}", pathLabel, userId);
        }
        return verified ? MfaStepResult.ok() : MfaStepResult.fail();
    }

    /**
     * Coerces the {@code embedding} payload field (a JSON array deserialized into
     * a {@code List<?>} of {@link Number}, or absent) into a {@code List<Double>}.
     * Returns null when the value is absent or not a list; a non-numeric element
     * makes the whole embedding invalid (null) so a malformed payload falls back
     * to the legacy image path rather than sending garbage to the bio service.
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

    private record InMemoryFaceImage(byte[] bytes) implements MultipartFile {
        @Override public String getName() { return "file"; }
        @Override public String getOriginalFilename() { return "face.jpg"; }
        @Override public String getContentType() { return "image/jpeg"; }
        @Override public boolean isEmpty() { return bytes.length == 0; }
        @Override public long getSize() { return bytes.length; }
        @Override public byte[] getBytes() { return bytes; }
        @Override public InputStream getInputStream() { return new ByteArrayInputStream(bytes); }
        @Override public void transferTo(java.io.File dest) throws java.io.IOException {
            java.nio.file.Files.write(dest.toPath(), bytes);
        }
    }
}
