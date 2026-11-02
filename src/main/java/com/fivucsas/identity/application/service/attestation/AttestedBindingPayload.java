package com.fivucsas.identity.application.service.attestation;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Canonical encoding of the payload an attested client signs for the attested
 * puzzle binding ({@code docs/ATTESTED_PUZZLE_BINDING.md} §4). Version 1:
 *
 * <pre>
 *   "FIVUCSAS-PUZZLE-BINDING-V1"            26 ASCII bytes, no terminator
 *   u32 len || puzzle_session_id            UTF-8
 *   u32 len || nonce                        raw bytes (32)
 *   u32 n   || n x f64                      embedding, IEEE-754 binary64, big-endian
 *   trace_digest                            32 raw bytes (bio's hex trace_digest, decoded)
 *   i64 t   || u32 n || n x i32             binding frame: timestamp + 96 landmark ints
 * </pre>
 *
 * <p>All integers are big-endian. The embedding is encoded from EXACTLY the
 * {@code List<Double>} that is forwarded to bio for the face match, so a signature
 * only verifies over the embedding that is actually matched. The client builds the
 * same bytes from the doubles it serializes into the request JSON (client-apps
 * {@code AttestedBindingPayload.kt}); a golden vector pins both sides.
 *
 * <p>The signature is ECDSA P-256 with SHA-256 (JCA {@code SHA256withECDSA},
 * ASN.1 DER signature) by the attested key.
 */
public final class AttestedBindingPayload {

    public static final String MAGIC = "FIVUCSAS-PUZZLE-BINDING-V1";
    public static final int VERSION = 1;
    public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    private AttestedBindingPayload() {
    }

    public static byte[] encode(String puzzleSessionId,
                                byte[] nonce,
                                List<Double> embedding,
                                byte[] traceDigest,
                                long bindingFrameT,
                                List<Long> bindingFrameCoords) {
        if (traceDigest == null || traceDigest.length != 32) {
            throw new IllegalArgumentException("trace digest must be 32 bytes");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(64 + 8 * embedding.size() + 4 * 96);
            DataOutputStream out = new DataOutputStream(bytes);
            out.write(MAGIC.getBytes(StandardCharsets.US_ASCII));
            byte[] sid = puzzleSessionId.getBytes(StandardCharsets.UTF_8);
            out.writeInt(sid.length);
            out.write(sid);
            out.writeInt(nonce.length);
            out.write(nonce);
            out.writeInt(embedding.size());
            for (Double d : embedding) {
                out.writeLong(Double.doubleToRawLongBits(d));
            }
            out.write(traceDigest);
            out.writeLong(bindingFrameT);
            out.writeInt(bindingFrameCoords.size());
            for (Long c : bindingFrameCoords) {
                long v = c;
                if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("binding frame coordinate out of int32 range");
                }
                out.writeInt((int) v);
            }
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
