package com.fivucsas.identity.application.service.attestation;

import com.fivucsas.identity.application.port.output.DeviceAttestationVerifierPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Application service for the attested puzzle binding
 * ({@code docs/ATTESTED_PUZZLE_BINDING.md}): parses the client's attestation bundle,
 * delegates platform attestation to {@link DeviceAttestationVerifierPort}, and
 * verifies the ECDSA signature over the canonical {@link AttestedBindingPayload}.
 *
 * <p>Wire shape (inside the PUZZLE {@code /auth/mfa/step} {@code data}):
 * <pre>
 * "attestation": {
 *   "format": "android-key",
 *   "payload_version": 1,
 *   "certificate_chain": ["&lt;base64 DER leaf&gt;", ..., "&lt;base64 DER root&gt;"],
 *   "signature": "&lt;base64 DER ECDSA signature&gt;",
 *   "trace_digest": "&lt;hex, optional diagnostics&gt;"
 * }
 * </pre>
 */
@Component
@Slf4j
public class AttestedPuzzleBindingVerifier {

    public static final String FORMAT_ANDROID_KEY = "android-key";
    static final int MAX_CHAIN_LENGTH = 10;
    static final int MAX_CERT_BYTES = 16 * 1024;
    static final int MAX_SIGNATURE_BYTES = 256;

    private final DeviceAttestationVerifierPort attestationVerifier;

    public AttestedPuzzleBindingVerifier(DeviceAttestationVerifierPort attestationVerifier) {
        this.attestationVerifier = attestationVerifier;
    }

    /** Parsed attestation bundle. */
    public record Evidence(String format, List<byte[]> chain, byte[] signature, String clientTraceDigestHex) {
    }

    /**
     * Parses the {@code attestation} object, or returns null when it is absent or
     * malformed in any way (unknown format/version, bad base64, size limits).
     */
    public static Evidence parseEvidence(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        Object format = map.get("format");
        if (!FORMAT_ANDROID_KEY.equals(format)) {
            return null;
        }
        Object version = map.get("payload_version");
        if (!(version instanceof Number n) || n.intValue() != AttestedBindingPayload.VERSION
                || n.doubleValue() != AttestedBindingPayload.VERSION) {
            return null;
        }
        Object chainRaw = map.get("certificate_chain");
        if (!(chainRaw instanceof List<?> list) || list.isEmpty() || list.size() > MAX_CHAIN_LENGTH) {
            return null;
        }
        List<byte[]> chain = new ArrayList<>(list.size());
        for (Object c : list) {
            byte[] der = decodeBase64(c);
            if (der == null || der.length == 0 || der.length > MAX_CERT_BYTES) {
                return null;
            }
            chain.add(der);
        }
        byte[] signature = decodeBase64(map.get("signature"));
        if (signature == null || signature.length == 0 || signature.length > MAX_SIGNATURE_BYTES) {
            return null;
        }
        Object digest = map.get("trace_digest");
        String digestHex = digest instanceof String s ? s.toLowerCase(Locale.ROOT) : null;
        return new Evidence(FORMAT_ANDROID_KEY, chain, signature, digestHex);
    }

    /** Verifies the platform attestation for {@code evidence} against the issued nonce. */
    public DeviceAttestationVerifierPort.Result verifyDevice(Evidence evidence, byte[] nonce) {
        try {
            DeviceAttestationVerifierPort.Result r =
                    attestationVerifier.verifyAndroidKeyAttestation(evidence.chain(), nonce);
            return r != null ? r : DeviceAttestationVerifierPort.Result.fail("VERIFIER_RETURNED_NULL");
        } catch (RuntimeException e) {
            log.error("Device attestation verifier threw — failing closed: {}", e.toString());
            return DeviceAttestationVerifierPort.Result.fail("VERIFIER_ERROR");
        }
    }

    /**
     * Decodes bio's {@code trace_digest} (64 lowercase/uppercase hex chars) or
     * returns null when absent/malformed.
     */
    public static byte[] decodeTraceDigest(Object raw) {
        if (!(raw instanceof String s) || s.length() != 64) {
            return null;
        }
        try {
            return HexFormat.of().parseHex(s.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Verifies {@code signature} (DER ECDSA) over {@code payload} with {@code key}. */
    public static boolean verifySignature(PublicKey key, byte[] signature, byte[] payload) {
        if (key == null || signature == null || payload == null) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(AttestedBindingPayload.SIGNATURE_ALGORITHM);
            verifier.initVerify(key);
            verifier.update(payload);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] decodeBase64(Object raw) {
        if (!(raw instanceof String s) || s.isEmpty()) {
            return null;
        }
        try {
            // Accept standard and URL-safe alphabets, with or without padding.
            String normalized = s.trim().replace('-', '+').replace('_', '/');
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
