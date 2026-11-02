package com.fivucsas.identity.infrastructure.attestation;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Parsed Android Key Attestation {@code KeyDescription} (AOSP schema, attestation
 * versions 1..400+), restricted to the fields the attested puzzle binding checks.
 *
 * <pre>
 * KeyDescription ::= SEQUENCE {
 *   attestationVersion         INTEGER,
 *   attestationSecurityLevel   SecurityLevel,   -- ENUMERATED 0 Software, 1 TEE, 2 StrongBox
 *   keyMintVersion             INTEGER,
 *   keyMintSecurityLevel       SecurityLevel,
 *   attestationChallenge       OCTET STRING,
 *   uniqueId                   OCTET STRING,
 *   softwareEnforced           AuthorizationList,
 *   hardwareEnforced           AuthorizationList }
 * AuthorizationList ::= SEQUENCE { [n] EXPLICIT ... }   -- tags strictly ascending
 * RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
 *                            verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING OPTIONAL }
 * AttestationApplicationId ::= SEQUENCE { package_infos SET OF AttestationPackageInfo,
 *                                         signature_digests SET OF OCTET STRING }
 * AttestationPackageInfo ::= SEQUENCE { package_name OCTET STRING, version INTEGER }
 * </pre>
 *
 * <p>Parsing is strict (see {@link Der}); any deviation is a parse failure, which the
 * verifier treats as a failed attestation.
 */
record AndroidKeyDescription(
        long attestationVersion,
        SecurityLevel attestationSecurityLevel,
        long keyMintVersion,
        SecurityLevel keyMintSecurityLevel,
        byte[] attestationChallenge,
        AuthorizationList softwareEnforced,
        AuthorizationList hardwareEnforced) {

    /** OID of the KeyDescription certificate extension. */
    static final String OID = "1.3.6.1.4.1.11129.2.1.17";

    // AuthorizationList tags used here (KeyMint Tag numbers with the type bits stripped).
    static final int TAG_PURPOSE = 1;
    static final int TAG_ALGORITHM = 2;
    static final int TAG_KEY_SIZE = 3;
    static final int TAG_EC_CURVE = 10;
    static final int TAG_ORIGIN = 702;
    static final int TAG_ROOT_OF_TRUST = 704;
    static final int TAG_ATTESTATION_APPLICATION_ID = 709;

    static final long PURPOSE_SIGN = 2;
    static final long ALGORITHM_EC = 3;
    static final long EC_CURVE_P_256 = 1;
    static final long ORIGIN_GENERATED = 0;

    enum SecurityLevel {
        SOFTWARE, TRUSTED_ENVIRONMENT, STRONG_BOX;

        static SecurityLevel of(long v) throws Der.DerException {
            return switch ((int) v) {
                case 0 -> SOFTWARE;
                case 1 -> TRUSTED_ENVIRONMENT;
                case 2 -> STRONG_BOX;
                default -> throw new Der.DerException("unknown security level " + v);
            };
        }
    }

    enum VerifiedBootState {
        VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED;

        static VerifiedBootState of(long v) throws Der.DerException {
            return switch ((int) v) {
                case 0 -> VERIFIED;
                case 1 -> SELF_SIGNED;
                case 2 -> UNVERIFIED;
                case 3 -> FAILED;
                default -> throw new Der.DerException("unknown verified boot state " + v);
            };
        }
    }

    record RootOfTrust(byte[] verifiedBootKey, boolean deviceLocked, VerifiedBootState verifiedBootState) {
    }

    record ApplicationId(List<String> packageNames, List<byte[]> signatureDigests) {
    }

    /** Raw AuthorizationList: tag number → the value inside the EXPLICIT tag. */
    record AuthorizationList(Map<Integer, Der.Value> entries) {

        Der.Value get(int tag) {
            return entries.get(tag);
        }

        Set<Long> integerSet(int tag) throws Der.DerException {
            Der.Value v = entries.get(tag);
            if (v == null) {
                return Collections.emptySet();
            }
            v.expectUniversal(Der.TAG_SET);
            Set<Long> out = new TreeSet<>();
            for (Der.Value e : v.children()) {
                out.add(e.expectUniversal(Der.TAG_INTEGER).nonNegativeLong());
            }
            return out;
        }

        Long integer(int tag) throws Der.DerException {
            Der.Value v = entries.get(tag);
            return v == null ? null : v.expectUniversal(Der.TAG_INTEGER).nonNegativeLong();
        }

        RootOfTrust rootOfTrust() throws Der.DerException {
            Der.Value v = entries.get(TAG_ROOT_OF_TRUST);
            if (v == null) {
                return null;
            }
            List<Der.Value> f = v.expectUniversal(Der.TAG_SEQUENCE).children();
            if (f.size() < 3 || f.size() > 4) {
                throw new Der.DerException("RootOfTrust must have 3 or 4 fields");
            }
            byte[] key = f.get(0).expectUniversal(Der.TAG_OCTET_STRING).octets();
            boolean locked = f.get(1).expectUniversal(Der.TAG_BOOLEAN).bool();
            VerifiedBootState state = VerifiedBootState.of(
                    f.get(2).expectUniversal(Der.TAG_ENUMERATED).nonNegativeLong());
            if (f.size() == 4) {
                f.get(3).expectUniversal(Der.TAG_OCTET_STRING).octets();
            }
            return new RootOfTrust(key, locked, state);
        }

        ApplicationId applicationId() throws Der.DerException {
            Der.Value v = entries.get(TAG_ATTESTATION_APPLICATION_ID);
            if (v == null) {
                return null;
            }
            byte[] encoded = v.expectUniversal(Der.TAG_OCTET_STRING).octets();
            List<Der.Value> f = Der.readSingle(encoded).expectUniversal(Der.TAG_SEQUENCE).children();
            if (f.size() != 2) {
                throw new Der.DerException("AttestationApplicationId must have 2 fields");
            }
            List<String> packages = new ArrayList<>();
            for (Der.Value info : f.get(0).expectUniversal(Der.TAG_SET).children()) {
                List<Der.Value> pf = info.expectUniversal(Der.TAG_SEQUENCE).children();
                if (pf.size() != 2) {
                    throw new Der.DerException("AttestationPackageInfo must have 2 fields");
                }
                packages.add(new String(pf.get(0).expectUniversal(Der.TAG_OCTET_STRING).octets(),
                        StandardCharsets.UTF_8));
                pf.get(1).expectUniversal(Der.TAG_INTEGER).integer();
            }
            List<byte[]> digests = new ArrayList<>();
            for (Der.Value d : f.get(1).expectUniversal(Der.TAG_SET).children()) {
                digests.add(d.expectUniversal(Der.TAG_OCTET_STRING).octets());
            }
            return new ApplicationId(packages, digests);
        }
    }

    /** True when the certificate carries a KeyDescription extension. */
    static boolean present(X509Certificate cert) {
        return cert.getExtensionValue(OID) != null;
    }

    /** Parses the KeyDescription extension of {@code cert}. */
    static AndroidKeyDescription parse(X509Certificate cert) throws Der.DerException {
        byte[] ext = cert.getExtensionValue(OID);
        if (ext == null) {
            throw new Der.DerException("KeyDescription extension missing");
        }
        // getExtensionValue returns the DER OCTET STRING wrapping extnValue.
        byte[] inner = Der.readSingle(ext).expectUniversal(Der.TAG_OCTET_STRING).octets();
        return parse(inner);
    }

    static AndroidKeyDescription parse(byte[] keyDescriptionDer) throws Der.DerException {
        List<Der.Value> f = Der.readSingle(keyDescriptionDer).expectUniversal(Der.TAG_SEQUENCE).children();
        if (f.size() != 8) {
            throw new Der.DerException("KeyDescription must have 8 fields, got " + f.size());
        }
        long attVersion = f.get(0).expectUniversal(Der.TAG_INTEGER).nonNegativeLong();
        SecurityLevel attLevel = SecurityLevel.of(f.get(1).expectUniversal(Der.TAG_ENUMERATED).nonNegativeLong());
        long kmVersion = f.get(2).expectUniversal(Der.TAG_INTEGER).nonNegativeLong();
        SecurityLevel kmLevel = SecurityLevel.of(f.get(3).expectUniversal(Der.TAG_ENUMERATED).nonNegativeLong());
        byte[] challenge = f.get(4).expectUniversal(Der.TAG_OCTET_STRING).octets();
        f.get(5).expectUniversal(Der.TAG_OCTET_STRING).octets(); // uniqueId (unused)
        AuthorizationList sw = authorizationList(f.get(6));
        AuthorizationList hw = authorizationList(f.get(7));
        return new AndroidKeyDescription(attVersion, attLevel, kmVersion, kmLevel, challenge, sw, hw);
    }

    private static AuthorizationList authorizationList(Der.Value seq) throws Der.DerException {
        seq.expectUniversal(Der.TAG_SEQUENCE);
        Map<Integer, Der.Value> entries = new LinkedHashMap<>();
        int last = -1;
        for (Der.Value e : seq.children()) {
            if (e.tagClass() != Der.CLASS_CONTEXT || !e.constructed()) {
                throw new Der.DerException("AuthorizationList entry must be an EXPLICIT context tag");
            }
            if (e.tagNumber() <= last) {
                throw new Der.DerException("AuthorizationList tags not in strictly ascending order");
            }
            last = e.tagNumber();
            entries.put(e.tagNumber(), e.explicitInner());
        }
        return new AuthorizationList(entries);
    }

    /** The lower of the two security levels (the effective one). */
    SecurityLevel effectiveSecurityLevel() {
        return attestationSecurityLevel.ordinal() <= keyMintSecurityLevel.ordinal()
                ? attestationSecurityLevel : keyMintSecurityLevel;
    }
}
