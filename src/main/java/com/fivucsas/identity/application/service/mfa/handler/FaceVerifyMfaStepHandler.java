package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.FaceEmbeddingLivenessPolicy;
import com.fivucsas.identity.application.service.mfa.LivenessEmbeddingDigest;
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
import java.util.LinkedHashMap;
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
    // Gap Ü2: what to do with an embedding FACE factor that has no liveness
    // factor (PUZZLE) before it. Default AUDIT = unchanged behaviour + audit.
    private final FaceEmbeddingLivenessPolicy livenessPolicy;
    private final AuditLogPort auditLogPort;

    /** Non-terminal status asking the client to re-send the step with an image. */
    public static final String STATUS_FACE_IMAGE_REQUIRED = "FACE_IMAGE_REQUIRED";
    static final String EVENT_UNPAIRED = "FACE_EMBEDDING_UNPAIRED";
    static final String EVENT_REROUTED_TO_IMAGE = "FACE_EMBEDDING_REROUTED_TO_IMAGE";
    static final String EVENT_IMAGE_REQUIRED = "FACE_IMAGE_REQUIRED";
    static final String EVENT_PAIRED = "FACE_EMBEDDING_PAIRED";

    /** How (or why not) this FACE embedding is backed by an earlier bound PUZZLE. */
    enum Pairing {
        /** An earlier PUZZLE's ATTESTED identity binding matched exactly this embedding. */
        PAIRED,
        /** No PUZZLE completed earlier in the session. */
        NO_PUZZLE,
        /**
         * A PUZZLE completed, but without ATTESTED identity binding (no embedding
         * pinned): liveness-only, or the non-attested binding check, which a
         * modified client can pass with an embedding that is not from the capture.
         */
        PUZZLE_NOT_BOUND,
        /** A bound PUZZLE pinned a different embedding than the one sent here. */
        EMBEDDING_MISMATCH
    }

    static Pairing pairingOf(MfaSession session, List<Double> embedding) {
        if (!session.getCompletedMethods().contains(AuthMethodType.PUZZLE.name())) {
            return Pairing.NO_PUZZLE;
        }
        String pinned = session.getLivenessEmbeddingSha256();
        if (pinned == null || pinned.isBlank()) {
            return Pairing.PUZZLE_NOT_BOUND;
        }
        return LivenessEmbeddingDigest.matches(pinned, embedding) ? Pairing.PAIRED : Pairing.EMBEDDING_MISMATCH;
    }

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
        // the pre-Phase-5 behaviour.
        //
        // LIVENESS (gap Ü2): an embedding carries no frame, so bio cannot run PAD
        // on it. The ONLY liveness evidence this handler accepts for an embedding
        // is a PUZZLE completed EARLIER in the same MFA session whose ATTESTED
        // identity binding ran and passed AND matched EXACTLY this embedding: the
        // PUZZLE handler pins the SHA-256 of the vector it matched on the session
        // (livenessEmbeddingSha256) only on the attested path (the device key
        // signed that vector with the scored trace), and this step must send the
        // same vector. A PUZZLE without binding proves only that SOME live person
        // did it, not whose face it was; the non-attested binding check compares
        // client data with client data, so a modified client can pass it with a
        // photo-derived embedding. Neither counts (pairing = NO_PUZZLE /
        // PUZZLE_NOT_BOUND / EMBEDDING_MISMATCH → unpaired).
        // FaceEmbeddingLivenessPolicy decides — BEFORE any matching, so the
        // response never reveals whether the face would have matched:
        //   OFF     → embedding path as before, no audit;
        //   AUDIT   → paired: embedding path + FACE_EMBEDDING_PAIRED audit;
        //             unpaired: embedding path + WARN + FACE_EMBEDDING_UNPAIRED audit;
        //   ENFORCE → paired: embedding path + FACE_EMBEDDING_PAIRED audit;
        //             unpaired with an image in the same payload: the image path
        //             (bio passive PAD), audit FACE_EMBEDDING_REROUTED_TO_IMAGE;
        //             unpaired, no image: a non-terminal FACE_IMAGE_REQUIRED
        //             challenge (no strike, no completed method, no advance),
        //             audit FACE_IMAGE_REQUIRED.
        // A PUZZLE completed AFTER FACE does not count (deliberate trade-off; no
        // production flow has that order).
        List<Double> embedding = extractEmbedding(data.get("embedding"));
        boolean embeddingPathEnabled =
                clientSideEmbeddingPolicy.isEnabledForTenant(session.getTenantId());
        if (embeddingPathEnabled && embedding != null && !embedding.isEmpty()) {
            FaceEmbeddingLivenessPolicy.Mode mode = livenessPolicy.modeFor(session.getTenantId());
            Pairing pairing = pairingOf(session, embedding);
            if (pairing == Pairing.PAIRED) {
                if (mode != FaceEmbeddingLivenessPolicy.Mode.OFF) {
                    audit(session, userId, EVENT_PAIRED, pairing);
                }
            } else if (mode == FaceEmbeddingLivenessPolicy.Mode.ENFORCE) {
                String image = imageOf(data);
                if (image != null) {
                    audit(session, userId, EVENT_REROUTED_TO_IMAGE, pairing);
                    log.info("AUDIT: unpaired FACE embedding ({}) re-routed to image path — userId={}, tenantId={}",
                            pairing, userId, session.getTenantId());
                    return verifyImage(userId, image);
                }
                audit(session, userId, EVENT_IMAGE_REQUIRED, pairing);
                log.info("AUDIT: unpaired FACE embedding ({}) refused, image capture required — userId={}, tenantId={}",
                        pairing, userId, session.getTenantId());
                return MfaStepResult.challenge(imageRequiredBody(session));
            } else if (mode == FaceEmbeddingLivenessPolicy.Mode.AUDIT) {
                log.warn("AUDIT: FACE embedding accepted without a bound liveness factor ({}) — userId={}, tenantId={}, step={}/{}",
                        pairing, userId, session.getTenantId(), session.getCurrentStep(), session.getTotalSteps());
                audit(session, userId, EVENT_UNPAIRED, pairing);
            }
            String tenantId = session.getTenantId() != null ? session.getTenantId().toString() : null;
            Map<String, Object> embeddingResult =
                    biometricService.verifyEmbedding(tenantId, userId, embedding);
            return interpretFaceResult(userId, embeddingResult, "embedding");
        }

        // --- Legacy image path (UNCHANGED) ---
        String image = imageOf(data);
        if (image == null) {
            return MfaStepResult.fail();
        }
        return verifyImage(userId, image);
    }

    /** The image path: bio /verify runs passive PAD on the frame, then matches. */
    private MfaStepResult verifyImage(java.util.UUID userId, String image) {
        byte[] bytes = Base64.getDecoder().decode(
                image.contains(",") ? image.substring(image.indexOf(",") + 1) : image);
        MultipartFile faceFile = new InMemoryFaceImage(bytes);

        Map<String, Object> faceResult = biometricService.verifyFace(userId, faceFile);
        return interpretFaceResult(userId, faceResult, "image");
    }

    private static String imageOf(Map<String, Object> data) {
        Object raw = data.get("image");
        if (raw instanceof String s && !s.isBlank()) {
            return s;
        }
        return null;
    }

    private static Map<String, Object> imageRequiredBody(MfaSession session) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", STATUS_FACE_IMAGE_REQUIRED);
        body.put("method", AuthMethodType.FACE.name());
        body.put("requiredInput", "image");
        body.put("currentStep", session.getCurrentStep());
        body.put("totalSteps", session.getTotalSteps());
        body.put("message", "Face verification requires an image capture");
        return body;
    }

    /**
     * Best-effort audit row (tenant, user, step, user agent; never the embedding).
     * An audit failure must never change the login outcome.
     */
    private void audit(MfaSession session, java.util.UUID userId, String eventType, Pairing pairing) {
        try {
            String details = "tenantId=" + session.getTenantId()
                    + ", step=" + session.getCurrentStep() + "/" + session.getTotalSteps()
                    + ", pairing=" + pairing
                    + ", userAgent=" + session.getUserAgent();
            auditLogPort.logSecurityEvent(userId.toString(), eventType, session.getIpAddress(), details);
        } catch (RuntimeException e) {
            log.warn("Failed to write {} audit event for userId={}: {}", eventType, userId, e.getMessage());
        }
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
