package com.fivucsas.identity.application.service.mfa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Gap Ü2: the digest that ties a FACE embedding step to the PUZZLE step whose
 * identity binding matched an embedding in the same MFA session.
 *
 * <p>A PUZZLE step with identity binding (puzzleConfig.alsoMatchFaceIdentity)
 * stores {@link #sha256Hex(List)} of the embedding it matched on the MFA
 * session. A later FACE step counts as backed by that liveness factor only
 * when its embedding has the same digest, i.e. it is exactly the vector the
 * PUZZLE matched. The digest covers the IEEE-754 bit pattern of each value in
 * order, so the same JSON array always gives the same digest, and any change to
 * any value gives a different one. The embedding itself is never stored.
 */
public final class LivenessEmbeddingDigest {

    private LivenessEmbeddingDigest() {
    }

    /** Lower-case hex SHA-256 over the big-endian double bits; null for a null or empty list. */
    public static String sha256Hex(List<Double> embedding) {
        if (embedding == null || embedding.isEmpty()) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES + embedding.size() * Double.BYTES);
        buf.putInt(embedding.size());
        for (Double v : embedding) {
            if (v == null) {
                return null;
            }
            buf.putLong(Double.doubleToLongBits(v));
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(buf.array()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Constant-time comparison of a stored digest with the digest of {@code embedding}. */
    public static boolean matches(String storedHex, List<Double> embedding) {
        String actual = sha256Hex(embedding);
        if (storedHex == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(storedHex.getBytes(StandardCharsets.US_ASCII),
                actual.getBytes(StandardCharsets.US_ASCII));
    }
}
