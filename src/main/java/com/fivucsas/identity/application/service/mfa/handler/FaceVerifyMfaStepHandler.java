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

    /** Same threshold as FaceAuthHandler — confidence fallback when {@code verified} is false. */
    private static final double CONFIDENCE_FALLBACK_THRESHOLD = 0.7;

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

        Map<String, Object> faceResult = biometricService.verifyFace(user.getId(), faceFile);

        // Anti-spoof: hard-fail if biometric-processor flagged the frame.
        Object errorCode = faceResult.get("error_code");
        if (errorCode instanceof String ec && "SPOOF_DETECTED".equals(ec)) {
            log.warn("AUDIT: MFA face spoof detected — userId={}", user.getId());
            return MfaStepResult.fail();
        }

        boolean verified = Boolean.TRUE.equals(faceResult.get("verified"))
                || "true".equalsIgnoreCase(String.valueOf(faceResult.get("verified")));
        if (!verified) {
            Object conf = faceResult.get("confidence");
            if (conf instanceof Number num && num.doubleValue() >= CONFIDENCE_FALLBACK_THRESHOLD) {
                verified = true;
            }
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
