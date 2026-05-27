package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
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
import java.util.Base64;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class FaceVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final BiometricServicePort biometricService;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.FACE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String image = (String) data.get("image");
        if (image == null || image.isBlank()) {
            return MfaStepResult.fail();
        }
        byte[] bytes = Base64.getDecoder().decode(
                image.contains(",") ? image.substring(image.indexOf(",") + 1) : image);
        MultipartFile faceFile = new InMemoryFaceImage(bytes);

        // Cache user-id once to keep the entity.User boundary surface
        // (ArchUnit UserDomainBoundaryTest) at one call site per method —
        // matches the pattern in FaceAuthHandler.
        java.util.UUID userId = user.getId();
        Map<String, Object> faceResult = biometricService.verifyFace(userId, faceFile);

        // Anti-spoof: hard-fail if biometric-processor flagged the frame.
        Object errorCode = faceResult.get("error_code");
        if (errorCode instanceof String ec && "SPOOF_DETECTED".equals(ec)) {
            log.warn("AUDIT: MFA face spoof detected — userId={}", userId);
            return MfaStepResult.fail();
        }

        // SECURITY (P0, BACKEND_REVIEW 2026-05-12): Trust ONLY the bio
        // processor's `verified` field. PR #83 removed the 0.7 cosine
        // confidence fallback in FaceAuthHandler + AuthController.verify2FAMethod
        // but missed this N-step MFA handler — which is the one hosted login
        // actually uses. The bio processor applies the adaptive aging
        // threshold (VERIFICATION_THRESHOLD_AGED_*) server-side; a
        // handler-side confidence fallback silently overrides that policy and
        // is a fail-open vector (INVESTIGATION_FAILOPEN_2026-05-07.md F3).
        // If `verified` is missing/null, treat it as a hard reject and log loudly.
        Object verifiedClaim = faceResult.get("verified");
        if (verifiedClaim == null) {
            log.error("AUDIT: MFA face verify missing `verified` field — userId={}, rejecting. response keys={}",
                    userId, faceResult.keySet());
            return MfaStepResult.fail();
        }
        boolean verified = Boolean.TRUE.equals(verifiedClaim)
                || "true".equalsIgnoreCase(String.valueOf(verifiedClaim));
        if (!verified) {
            log.warn("AUDIT: MFA face verify failed (server verified=false) — userId={}", userId);
        }
        return verified ? MfaStepResult.ok() : MfaStepResult.fail();
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
