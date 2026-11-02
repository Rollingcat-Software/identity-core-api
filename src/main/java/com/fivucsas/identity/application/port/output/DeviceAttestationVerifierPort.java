package com.fivucsas.identity.application.port.output;

import java.security.PublicKey;
import java.util.List;

/**
 * Output port: verifies hardware-backed device key attestation evidence for the
 * attested puzzle binding ({@code docs/ATTESTED_PUZZLE_BINDING.md}).
 *
 * <p>The adapter owns all platform specifics (Android Key Attestation today, iOS
 * App Attest later): certificate-chain validation to the pinned vendor roots,
 * revocation, and the platform claims (challenge, security level, app identity,
 * boot state). The application layer only receives a verdict plus the attested
 * public key, which it then uses to verify the signature over the canonical
 * binding payload.
 */
public interface DeviceAttestationVerifierPort {

    /**
     * Verifies an Android Key Attestation certificate chain.
     *
     * @param certificateChainDer DER certificates, leaf (the attested key) first,
     *                            root last (the root may be omitted)
     * @param expectedChallenge   the single-use nonce the server issued; must equal
     *                            the KeyDescription {@code attestationChallenge}
     * @return a verdict; never null and never throws for bad input (fail closed)
     */
    Result verifyAndroidKeyAttestation(List<byte[]> certificateChainDer, byte[] expectedChallenge);

    /**
     * Verification verdict. When {@code valid} is false, {@code reason} is a stable
     * machine-readable code (e.g. {@code CHALLENGE_MISMATCH}) and the other fields
     * may be null.
     */
    record Result(boolean valid,
                  String reason,
                  PublicKey attestedPublicKey,
                  String securityLevel,
                  String packageName,
                  String verifiedBootState,
                  Boolean deviceLocked) {

        public static Result fail(String reason) {
            return new Result(false, reason, null, null, null, null, null);
        }

        public static Result ok(PublicKey key, String securityLevel, String packageName,
                                String verifiedBootState, boolean deviceLocked) {
            return new Result(true, null, key, securityLevel, packageName, verifiedBootState, deviceLocked);
        }
    }
}
