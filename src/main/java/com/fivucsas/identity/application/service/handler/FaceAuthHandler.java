package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class FaceAuthHandler implements AuthMethodHandler {

    private final BiometricServicePort biometricServicePort;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.FACE;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String imageBase64 = (String) data.get("image");

        if (imageBase64 == null || imageBase64.isEmpty()) {
            return StepResult.failure("Face image is required");
        }

        // Strip data URI prefix if present (frontend may send "data:image/jpeg;base64,...")
        if (imageBase64.contains(",")) {
            imageBase64 = imageBase64.substring(imageBase64.indexOf(",") + 1);
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before face verification");
        }

        // Cache the user-id once — keeps the entity.User boundary surface (ArchUnit
        // UserDomainBoundaryTest) to a single call site within this method.
        java.util.UUID userId = session.getUser().getId();

        try {
            byte[] imageBytes = Base64.getDecoder().decode(imageBase64);
            MultipartFile imageFile = new Base64MultipartFile(imageBytes, "face.jpg", "image/jpeg");

            Map<String, Object> result = biometricServicePort.verifyFace(
                    userId, imageFile);

            // Check for spoof detection (anti-spoofing from biometric processor)
            String errorCode = result.get("error_code") instanceof String ec ? ec : null;
            if ("SPOOF_DETECTED".equals(errorCode)) {
                log.warn("Spoof detected for user: {}, score: {}",
                        session.getUser().getEmail(), result.get("antispoof_score"));
                return StepResult.failure("Spoof detected: please use a live face, not a photo or screen");
            }

            // SECURITY (P0-#10): Trust ONLY the bio processor's `verified` field.
            // The bio processor applies the adaptive aging threshold
            // (VERIFICATION_THRESHOLD_AGED_*) server-side. A client/handler-side
            // confidence fallback (e.g., >= 0.7) silently overrides that policy and
            // is a fail-open vector — see INVESTIGATION_FAILOPEN_2026-05-07.md F3.
            // If `verified` is missing/null, treat it as a hard reject and log loudly.
            Object verified = result.get("verified");
            if (verified == null) {
                log.error("AUDIT: face verify missing `verified` field — userId={}, rejecting. response keys={}",
                        userId, result.keySet());
                return StepResult.failure("Face verification failed");
            }

            boolean isVerified = Boolean.TRUE.equals(verified)
                    || "true".equalsIgnoreCase(String.valueOf(verified));

            if (isVerified) {
                log.info("Face verification successful for user: {}", session.getUser().getEmail());
                return StepResult.success(Map.of("verified", "true"));
            } else {
                log.warn("Face verification failed for user: {} (server verified=false)",
                        session.getUser().getEmail());
                return StepResult.failure("Face verification failed");
            }
        } catch (Exception e) {
            log.error("Face verification error for session: {}", session.getId(), e);
            return StepResult.failure("Face verification service unavailable");
        }
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("image");
    }

    /**
     * Lightweight MultipartFile implementation wrapping a byte array from base64 decode.
     */
    private record Base64MultipartFile(byte[] content, String filename, String contentType) implements MultipartFile {
        @Override
        public String getName() { return "image"; }

        @Override
        public String getOriginalFilename() { return filename; }

        @Override
        public String getContentType() { return contentType; }

        @Override
        public boolean isEmpty() { return content == null || content.length == 0; }

        @Override
        public long getSize() { return content != null ? content.length : 0; }

        @Override
        public byte[] getBytes() { return content; }

        @Override
        public InputStream getInputStream() { return new ByteArrayInputStream(content); }

        @Override
        public void transferTo(File dest) {
            throw new UnsupportedOperationException("transferTo not supported for in-memory multipart file");
        }
    }
}
