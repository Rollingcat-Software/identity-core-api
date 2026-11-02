package com.fivucsas.identity.infrastructure.attestation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Test-only generator of synthetic Android-Key-Attestation-shaped certificate
 * chains (root → intermediate → leaf with a KeyDescription extension), built with
 * a tiny DER writer and signed with JCA ECDSA. BouncyCastle is not on the classpath
 * (and the build is offline), so this hand-rolled encoder stands in for it; the
 * parser is cross-checked against REAL device chains in {@code keyattestation-samples}.
 */
final class TestAttestationChains {

    static final String ECDSA_SHA256_OID = "1.2.840.10045.4.3.2";

    private TestAttestationChains() {
    }

    // ------------------------------------------------------------------ DER writer

    static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeTag(out, tag);
        writeLength(out, content.length);
        out.writeBytes(content);
        return out.toByteArray();
    }

    /** tag encoding: low byte = class|constructed|number (<31); use {@link #explicit} for high tags. */
    private static void writeTag(ByteArrayOutputStream out, int tag) {
        out.write(tag);
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len < 0x100) {
            out.write(0x81);
            out.write(len);
        } else if (len < 0x10000) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        } else {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    static byte[] seq(byte[]... items) {
        return tlv(0x30, concat(items));
    }

    static byte[] set(byte[]... items) {
        return tlv(0x31, concat(items));
    }

    static byte[] integer(long v) {
        return tlv(0x02, BigInteger.valueOf(v).toByteArray());
    }

    static byte[] integer(BigInteger v) {
        return tlv(0x02, v.toByteArray());
    }

    static byte[] enumerated(long v) {
        return tlv(0x0A, BigInteger.valueOf(v).toByteArray());
    }

    static byte[] octets(byte[] v) {
        return tlv(0x04, v);
    }

    static byte[] bool(boolean v) {
        return tlv(0x01, new byte[]{(byte) (v ? 0xFF : 0x00)});
    }

    static byte[] utf8(String s) {
        return tlv(0x0C, s.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] bitString(byte[] v) {
        return tlv(0x03, concat(new byte[]{0}, v));
    }

    static byte[] generalizedTime(Instant t) {
        String s = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC).format(t);
        return tlv(0x18, s.getBytes(StandardCharsets.US_ASCII));
    }

    static byte[] oid(String dotted) {
        String[] p = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(p[0]) * 40 + Integer.parseInt(p[1]));
        for (int i = 2; i < p.length; i++) {
            long v = Long.parseLong(p[i]);
            byte[] tmp = new byte[10];
            int n = 0;
            do {
                tmp[n++] = (byte) (v & 0x7F);
                v >>>= 7;
            } while (v != 0);
            for (int j = n - 1; j >= 0; j--) {
                out.write(tmp[j] | (j > 0 ? 0x80 : 0));
            }
        }
        return tlv(0x06, out.toByteArray());
    }

    /** EXPLICIT context-specific constructed tag [n] wrapping {@code inner}. */
    static byte[] explicit(int n, byte[] inner) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (n < 31) {
            out.write(0xA0 | n);
        } else {
            out.write(0xBF);
            byte[] tmp = new byte[5];
            int k = 0;
            int v = n;
            do {
                tmp[k++] = (byte) (v & 0x7F);
                v >>>= 7;
            } while (v != 0);
            for (int j = k - 1; j >= 0; j--) {
                out.write(tmp[j] | (j > 0 ? 0x80 : 0));
            }
        }
        writeLength(out, inner.length);
        out.writeBytes(inner);
        return out.toByteArray();
    }

    static byte[] name(String cn, String org) {
        List<byte[]> rdns = new ArrayList<>();
        if (org != null) {
            rdns.add(set(seq(oid("2.5.4.10"), utf8(org))));
        }
        rdns.add(set(seq(oid("2.5.4.3"), utf8(cn))));
        return seq(rdns.toArray(new byte[0][]));
    }

    // ------------------------------------------------------------------ KeyDescription

    /** Mutable description of the KeyDescription to emit. */
    static final class Kd {
        long attestationVersion = 300;
        int attestationSecurityLevel = 1; // TEE
        int keyMintSecurityLevel = 1;
        byte[] challenge = new byte[32];
        String packageName = "com.fivucsas.mobile";
        byte[] signingCertDigest = new byte[32];
        long origin = 0; // GENERATED
        long purpose = 2; // SIGN
        long algorithm = 3; // EC
        long ecCurve = 1; // P-256
        boolean deviceLocked = true;
        int verifiedBootState = 0; // VERIFIED
        boolean emitRootOfTrust = true;
        boolean swapTagOrder = false;

        byte[] encode() {
            byte[] appId = seq(
                    set(seq(octets(packageName.getBytes(StandardCharsets.UTF_8)), integer(1))),
                    set(octets(signingCertDigest)));
            byte[] sw = seq(explicit(709, octets(appId)));
            List<byte[]> hw = new ArrayList<>();
            hw.add(explicit(1, set(integer(purpose))));
            hw.add(explicit(2, integer(algorithm)));
            hw.add(explicit(3, integer(256)));
            hw.add(explicit(10, integer(ecCurve)));
            hw.add(explicit(702, integer(origin)));
            if (emitRootOfTrust) {
                hw.add(explicit(704, seq(octets(new byte[32]), bool(deviceLocked),
                        enumerated(verifiedBootState), octets(new byte[32]))));
            }
            if (swapTagOrder) {
                byte[] first = hw.remove(0);
                hw.add(first);
            }
            return seq(integer(attestationVersion), enumerated(attestationSecurityLevel),
                    integer(attestationVersion), enumerated(keyMintSecurityLevel),
                    octets(challenge), octets(new byte[0]), sw, seq(hw.toArray(new byte[0][])));
        }
    }

    // ------------------------------------------------------------------ certificates

    static X509Certificate cert(byte[] subject, byte[] issuer, PublicKey subjectKey, PrivateKey issuerKey,
                                Instant notBefore, Instant notAfter, long serial,
                                byte[] keyDescription, boolean ca) {
        try {
            byte[] algId = seq(oid(ECDSA_SHA256_OID));
            List<byte[]> exts = new ArrayList<>();
            if (ca) {
                exts.add(seq(oid("2.5.29.19"), bool(true), octets(seq(bool(true)))));
            }
            if (keyDescription != null) {
                exts.add(seq(oid(AndroidKeyDescription.OID), octets(keyDescription)));
            }
            List<byte[]> tbsParts = new ArrayList<>(List.of(
                    explicit(0, integer(2)),
                    integer(serial),
                    algId,
                    issuer,
                    seq(generalizedTime(notBefore), generalizedTime(notAfter)),
                    subject,
                    subjectKey.getEncoded()));
            if (!exts.isEmpty()) {
                tbsParts.add(explicit(3, seq(exts.toArray(new byte[0][]))));
            }
            byte[] tbs = seq(tbsParts.toArray(new byte[0][]));
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(issuerKey);
            s.update(tbs);
            byte[] der = seq(tbs, algId, bitString(s.sign()));
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair ecKeyPair(String curve) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(curve));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A complete synthetic chain: leaf (attested key), TEE intermediate, root. */
    record Chain(KeyPair root, KeyPair intermediate, KeyPair leaf,
                 X509Certificate rootCert, X509Certificate intermediateCert, X509Certificate leafCert) {

        List<byte[]> der() {
            return List.of(encoded(leafCert), encoded(intermediateCert), encoded(rootCert));
        }
    }

    static byte[] encoded(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Chain chain(Kd kd, Instant now) {
        KeyPair root = ecKeyPair("secp256r1");
        KeyPair inter = ecKeyPair("secp256r1");
        KeyPair leaf = ecKeyPair("secp256r1");
        byte[] rootName = name("Test Attestation Root", "Test");
        byte[] interName = name("test-tee-intermediate", "TEE");
        X509Certificate rootCert = cert(rootName, rootName, root.getPublic(), root.getPrivate(),
                now.minusSeconds(86_400 * 365L), now.plusSeconds(86_400 * 3650L), 1, null, true);
        X509Certificate interCert = cert(interName, rootName, inter.getPublic(), root.getPrivate(),
                now.minusSeconds(86_400L), now.plusSeconds(86_400 * 30L), 0x1234, null, true);
        X509Certificate leafCert = cert(name("Android Keystore Key", null), interName, leaf.getPublic(),
                inter.getPrivate(), Instant.EPOCH, Instant.parse("2048-01-01T00:00:00Z"), 1, kd.encode(), false);
        return new Chain(root, inter, leaf, rootCert, interCert, leafCert);
    }
}
