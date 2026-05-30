package com.fivucsas.identity.infrastructure.webauthn;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.UUID;

/**
 * Encodes/decodes the WebAuthn user handle
 * ({@code PublicKeyCredentialUserEntity.id}) used for discoverable passkeys.
 *
 * <p>A user handle is an opaque byte string (1–64 bytes per the WebAuthn spec)
 * that the RP supplies at registration and the authenticator echoes back on a
 * usernameless assertion. We derive it deterministically from the owning
 * {@link UUID} (16 raw bytes), stored and transported base64url-encoded so it
 * survives JSON and DB {@code varchar} columns unchanged.</p>
 *
 * <p>The encoding is reversible: a handle received on assertion is decoded back
 * to the {@code UUID} to resolve the user — no DB lookup table needed — and we
 * also persist the encoded form on the credential row so resolution can fall
 * back to a direct column match.</p>
 */
public final class WebAuthnUserHandle {

    private WebAuthnUserHandle() {
    }

    /** base64url(no padding) of the 16 UUID bytes. */
    public static String encode(UUID userId) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.putLong(userId.getMostSignificantBits());
        buf.putLong(userId.getLeastSignificantBits());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
    }

    /**
     * Decodes a base64url (or standard base64) user handle back to its
     * {@link UUID}. Accepts either encoding because some clients re-encode the
     * ArrayBuffer with standard base64 ({@code +} / {@code /}). Returns
     * {@code null} when the input is missing or not a valid 16-byte handle.
     */
    public static UUID decodeToUserId(String handle) {
        if (handle == null || handle.isBlank()) {
            return null;
        }
        try {
            String normalized = handle.replace('+', '-').replace('/', '_').replaceAll("=+$", "");
            byte[] bytes = Base64.getUrlDecoder().decode(normalized);
            if (bytes.length != 16) {
                return null;
            }
            ByteBuffer buf = ByteBuffer.wrap(bytes);
            long hi = buf.getLong();
            long lo = buf.getLong();
            return new UUID(hi, lo);
        } catch (RuntimeException e) {
            return null;
        }
    }
}
