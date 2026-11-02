package com.fivucsas.identity.infrastructure.attestation;

import com.fivucsas.identity.application.port.output.DeviceAttestationVerifierPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Android Key Attestation verifier ({@link DeviceAttestationVerifierPort} adapter)
 * for the attested puzzle binding ({@code docs/ATTESTED_PUZZLE_BINDING.md} §5).
 *
 * <p>Checks, in order (any failure ⇒ {@code Result.fail(<code>)}):
 * <ol>
 *   <li>The chain parses, ends at (or is issued by) a PINNED Google hardware
 *       attestation root (pinned by SubjectPublicKeyInfo), and every certificate
 *       is issued and signed by the next one.</li>
 *   <li>Validity of every certificate except the leaf (device-set, may be skewed)
 *       and the pinned anchor; an expired FACTORY-provisioned chain is tolerated, as
 *       in Google's reference verifier (factory keys cannot be rotated).</li>
 *   <li>Only the leaf carries the KeyDescription extension (blocks a chain extended
 *       by signing a fake certificate with a genuinely attested key).</li>
 *   <li>No certificate's serial is on Google's attestation status list
 *       (REVOKED / SUSPENDED), with a configurable fail policy when the list is
 *       unavailable.</li>
 *   <li>KeyDescription: challenge == issued nonce; effective security level TEE or
 *       StrongBox (StrongBox optionally required; for remotely provisioned chains
 *       the attestation certificate's {@code O=} must agree); key generated in
 *       hardware with SIGN purpose; leaf key is EC P-256; RootOfTrust
 *       verifiedBootState VERIFIED and deviceLocked (each configurable); the
 *       attestationApplicationId lists only allowed packages and only allowed
 *       signing-certificate SHA-256 digests.</li>
 * </ol>
 */
@Component
@Slf4j
public class AndroidKeyAttestationVerifierAdapter implements DeviceAttestationVerifierPort {

    static final String ROOTS_RESOURCE = "/attestation/google-hardware-attestation-roots.pem";

    /** Operator configuration (see application.yml {@code app.auth.attestation.android.*}). */
    record Settings(Set<String> packageNames,
                    Set<String> signingCertSha256,
                    boolean requireStrongBox,
                    boolean requireVerifiedBoot,
                    boolean requireDeviceLocked,
                    boolean revocationEnabled,
                    boolean revocationFailOpen,
                    Duration clockSkew) {
    }

    private final List<PublicKey> pinnedRoots;
    private final List<X509Certificate> pinnedRootCerts;
    private final Settings settings;
    private final GoogleAttestationStatusList statusList;
    private final Clock clock;
    private final ECParameterSpec p256;

    @Autowired
    public AndroidKeyAttestationVerifierAdapter(
            @Value("${app.auth.attestation.android.package:com.fivucsas.mobile}") String packages,
            @Value("${app.auth.attestation.android.signing-cert-sha256:}") String signingCerts,
            @Value("${app.auth.attestation.android.require-strongbox:false}") boolean requireStrongBox,
            @Value("${app.auth.attestation.android.require-verified-boot:true}") boolean requireVerifiedBoot,
            @Value("${app.auth.attestation.android.require-device-locked:true}") boolean requireDeviceLocked,
            @Value("${app.auth.attestation.android.revocation.enabled:true}") boolean revocationEnabled,
            @Value("${app.auth.attestation.android.revocation.url:https://android.googleapis.com/attestation/status}")
            String revocationUrl,
            @Value("${app.auth.attestation.android.revocation.cache-ttl:PT1H}") Duration revocationTtl,
            @Value("${app.auth.attestation.android.revocation.max-stale:PT24H}") Duration revocationMaxStale,
            @Value("${app.auth.attestation.android.revocation.fail-policy:closed}") String failPolicy,
            @Value("${app.auth.attestation.android.clock-skew:PT5M}") Duration clockSkew) {
        this(loadPinnedRoots(),
                new Settings(splitCsv(packages, false), normalizeDigests(splitCsv(signingCerts, false)),
                        requireStrongBox, requireVerifiedBoot, requireDeviceLocked, revocationEnabled,
                        "open".equalsIgnoreCase(failPolicy == null ? "" : failPolicy.trim()), clockSkew),
                new GoogleAttestationStatusList(
                        GoogleAttestationStatusList.httpFetcher(revocationUrl, Duration.ofSeconds(5)),
                        revocationTtl, revocationMaxStale, Clock.systemUTC()),
                Clock.systemUTC());
        if (this.settings.signingCertSha256().isEmpty()) {
            log.warn("app.auth.attestation.android.signing-cert-sha256 is empty — every Android attestation "
                    + "will be rejected (APP_SIGNATURE_NOT_ALLOWED) until the release signing-cert digest is set");
        }
    }

    AndroidKeyAttestationVerifierAdapter(List<X509Certificate> pinnedRootCerts, Settings settings,
                                         GoogleAttestationStatusList statusList, Clock clock) {
        this.pinnedRootCerts = List.copyOf(pinnedRootCerts);
        this.pinnedRoots = pinnedRootCerts.stream().map(X509Certificate::getPublicKey).toList();
        this.settings = settings;
        this.statusList = statusList;
        this.clock = clock;
        this.p256 = p256Params();
    }

    @Override
    public Result verifyAndroidKeyAttestation(List<byte[]> certificateChainDer, byte[] expectedChallenge) {
        try {
            return verify(certificateChainDer, expectedChallenge);
        } catch (RuntimeException e) {
            log.warn("Android attestation verification error — failing closed: {}", e.toString());
            return Result.fail("VERIFICATION_ERROR");
        }
    }

    private Result verify(List<byte[]> chainDer, byte[] expectedChallenge) {
        if (chainDer == null || chainDer.isEmpty() || expectedChallenge == null || expectedChallenge.length == 0) {
            return Result.fail("MISSING_INPUT");
        }
        if (settings.packageNames().isEmpty()) {
            return Result.fail("NOT_CONFIGURED");
        }

        List<X509Certificate> certs = new ArrayList<>(chainDer.size());
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (byte[] der : chainDer) {
                certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
            }
        } catch (CertificateException | ClassCastException e) {
            return Result.fail("CHAIN_PARSE_ERROR");
        }

        // ---- 1. Anchor: pinned root key (the chain may or may not include the root).
        X509Certificate last = certs.get(certs.size() - 1);
        List<X509Certificate> path;
        PublicKey anchorKey;
        X500Principal anchorSubject;
        if (isPinned(last.getPublicKey())) {
            path = certs.subList(0, certs.size() - 1);
            anchorKey = last.getPublicKey();
            anchorSubject = last.getSubjectX500Principal();
        } else {
            X509Certificate issuer = pinnedRootCerts.stream()
                    .filter(r -> r.getSubjectX500Principal().equals(last.getIssuerX500Principal()))
                    .filter(r -> signedBy(last, r.getPublicKey()))
                    .findFirst()
                    .orElse(null);
            if (issuer == null) {
                return Result.fail("UNTRUSTED_ROOT");
            }
            path = certs;
            anchorKey = issuer.getPublicKey();
            anchorSubject = issuer.getSubjectX500Principal();
        }
        if (path.size() < 2) {
            return Result.fail("CHAIN_TOO_SHORT");
        }
        boolean factoryProvisioned = isFactoryProvisioned(path.get(path.size() - 1));
        boolean remotelyProvisioned = isRemotelyProvisioned(path.get(path.size() - 1));

        // ---- 2. Walk root → leaf: name chaining, signatures, validity, extension placement.
        Instant now = clock.instant();
        PublicKey prevKey = anchorKey;
        X500Principal prevSubject = anchorSubject;
        for (int i = path.size() - 1; i >= 0; i--) {
            X509Certificate cert = path.get(i);
            if (!cert.getIssuerX500Principal().equals(prevSubject)) {
                return Result.fail("NAME_CHAINING");
            }
            if (!signedBy(cert, prevKey)) {
                return Result.fail("BAD_CERT_SIGNATURE");
            }
            if (i > 0) {
                String validity = checkValidity(cert, now, factoryProvisioned);
                if (validity != null) {
                    return Result.fail(validity);
                }
                if (AndroidKeyDescription.present(cert)) {
                    return Result.fail("EXTRA_ATTESTATION_EXTENSION");
                }
            }
            prevKey = cert.getPublicKey();
            prevSubject = cert.getSubjectX500Principal();
        }

        // ---- 3. Revocation (Google attestation status list).
        if (settings.revocationEnabled()) {
            Optional<Set<String>> revoked = statusList.revokedSerials();
            if (revoked.isEmpty()) {
                if (!settings.revocationFailOpen()) {
                    return Result.fail("REVOCATION_STATUS_UNAVAILABLE");
                }
                log.warn("Android attestation status list unavailable — proceeding (fail-policy=open)");
            } else {
                for (X509Certificate cert : certs) {
                    if (revoked.get().contains(cert.getSerialNumber().toString(16))) {
                        return Result.fail("CERT_REVOKED");
                    }
                }
            }
        }

        // ---- 4. KeyDescription of the leaf (the attested key).
        X509Certificate leaf = path.get(0);
        AndroidKeyDescription kd;
        try {
            kd = AndroidKeyDescription.parse(leaf);
        } catch (Der.DerException e) {
            return Result.fail("KEY_DESCRIPTION_INVALID");
        }
        if (!MessageDigest.isEqual(kd.attestationChallenge(), expectedChallenge)) {
            return Result.fail("CHALLENGE_MISMATCH");
        }
        AndroidKeyDescription.SecurityLevel level = kd.effectiveSecurityLevel();
        if (level == AndroidKeyDescription.SecurityLevel.SOFTWARE) {
            return Result.fail("SOFTWARE_SECURITY_LEVEL");
        }
        if (settings.requireStrongBox() && level != AndroidKeyDescription.SecurityLevel.STRONG_BOX) {
            return Result.fail("STRONGBOX_REQUIRED");
        }
        if (remotelyProvisioned) {
            String org = rdnValue(path.get(1).getSubjectX500Principal(), "O");
            String expectedOrg = kd.attestationSecurityLevel() == AndroidKeyDescription.SecurityLevel.STRONG_BOX
                    ? "StrongBox" : "TEE";
            if (!expectedOrg.equals(org)) {
                return Result.fail("SECURITY_LEVEL_CHAIN_MISMATCH");
            }
        }

        String keyCheck;
        String bootState;
        boolean deviceLocked;
        String packageName;
        try {
            keyCheck = checkKeyProperties(kd, leaf.getPublicKey());
            if (keyCheck != null) {
                return Result.fail(keyCheck);
            }
            AndroidKeyDescription.RootOfTrust rot = kd.hardwareEnforced().rootOfTrust();
            if (rot == null) {
                return Result.fail("ROOT_OF_TRUST_MISSING");
            }
            bootState = rot.verifiedBootState().name();
            deviceLocked = rot.deviceLocked();
            if (settings.requireVerifiedBoot()
                    && rot.verifiedBootState() != AndroidKeyDescription.VerifiedBootState.VERIFIED) {
                return Result.fail("BOOT_STATE_NOT_VERIFIED");
            }
            if (settings.requireDeviceLocked() && !rot.deviceLocked()) {
                return Result.fail("DEVICE_UNLOCKED");
            }

            AndroidKeyDescription.ApplicationId appId = kd.softwareEnforced().applicationId();
            if (appId == null) {
                appId = kd.hardwareEnforced().applicationId();
            }
            if (appId == null || appId.packageNames().isEmpty()) {
                return Result.fail("APP_ID_MISSING");
            }
            for (String pkg : appId.packageNames()) {
                if (!settings.packageNames().contains(pkg)) {
                    return Result.fail("APP_PACKAGE_NOT_ALLOWED");
                }
            }
            if (appId.signatureDigests().isEmpty()) {
                return Result.fail("APP_SIGNATURE_NOT_ALLOWED");
            }
            for (byte[] digest : appId.signatureDigests()) {
                if (!settings.signingCertSha256().contains(HexFormat.of().formatHex(digest))) {
                    return Result.fail("APP_SIGNATURE_NOT_ALLOWED");
                }
            }
            packageName = appId.packageNames().get(0);
        } catch (Der.DerException e) {
            return Result.fail("KEY_DESCRIPTION_INVALID");
        }

        return Result.ok(leaf.getPublicKey(), level.name(), packageName, bootState, deviceLocked);
    }

    private String checkKeyProperties(AndroidKeyDescription kd, PublicKey leafKey) throws Der.DerException {
        AndroidKeyDescription.AuthorizationList hw = kd.hardwareEnforced();
        Long origin = hw.integer(AndroidKeyDescription.TAG_ORIGIN);
        if (origin == null || origin != AndroidKeyDescription.ORIGIN_GENERATED) {
            return "KEY_NOT_GENERATED_IN_HARDWARE";
        }
        if (!hw.integerSet(AndroidKeyDescription.TAG_PURPOSE).contains(AndroidKeyDescription.PURPOSE_SIGN)) {
            return "KEY_PURPOSE_NOT_SIGN";
        }
        Long algorithm = hw.integer(AndroidKeyDescription.TAG_ALGORITHM);
        if (algorithm == null || algorithm != AndroidKeyDescription.ALGORITHM_EC) {
            return "KEY_NOT_EC_P256";
        }
        Long curve = hw.integer(AndroidKeyDescription.TAG_EC_CURVE);
        if (curve != null && curve != AndroidKeyDescription.EC_CURVE_P_256) {
            return "KEY_NOT_EC_P256";
        }
        if (!(leafKey instanceof ECPublicKey ec) || !isP256(ec.getParams())) {
            return "KEY_NOT_EC_P256";
        }
        return null;
    }

    private String checkValidity(X509Certificate cert, Instant now, boolean factoryProvisioned) {
        try {
            cert.checkValidity(Date.from(now));
            return null;
        } catch (CertificateNotYetValidException e) {
            try {
                cert.checkValidity(Date.from(now.plus(settings.clockSkew())));
                return null;
            } catch (CertificateExpiredException | CertificateNotYetValidException e2) {
                return "CERT_NOT_YET_VALID";
            }
        } catch (CertificateExpiredException e) {
            // Factory-provisioned keys cannot be rotated; Google's verifier tolerates
            // their expiry (the status list is the control for those chains).
            return factoryProvisioned ? null : "CERT_EXPIRED";
        }
    }

    private boolean isPinned(PublicKey key) {
        byte[] enc = key.getEncoded();
        return pinnedRoots.stream().anyMatch(r -> Arrays.equals(r.getEncoded(), enc));
    }

    private static boolean signedBy(X509Certificate cert, PublicKey key) {
        try {
            cert.verify(key);
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** Factory-provisioned: the certificate just below the root has a serialNumber RDN. */
    private static boolean isFactoryProvisioned(X509Certificate topIntermediate) {
        return topIntermediate.getSubjectX500Principal().getName(X500Principal.RFC1779)
                .contains("OID.2.5.4.5=");
    }

    /** Remotely provisioned (RKP): the certificate just below the root is Google's "Droid CA2". */
    private static boolean isRemotelyProvisioned(X509Certificate topIntermediate) {
        X500Principal p = topIntermediate.getSubjectX500Principal();
        return "Droid CA2".equals(rdnValue(p, "CN")) && "Google LLC".equals(rdnValue(p, "O"));
    }

    private static String rdnValue(X500Principal principal, String key) {
        for (String part : principal.getName(X500Principal.RFC1779).split(",")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length == 2 && kv[0].trim().equals(key)) {
                String v = kv[1].trim();
                if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1);
                }
                return v;
            }
        }
        return null;
    }

    private boolean isP256(ECParameterSpec spec) {
        return spec != null
                && spec.getOrder().equals(p256.getOrder())
                && spec.getCurve().equals(p256.getCurve())
                && spec.getGenerator().equals(p256.getGenerator())
                && spec.getCofactor() == p256.getCofactor();
    }

    private static ECParameterSpec p256Params() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 parameters unavailable", e);
        }
    }

    static List<X509Certificate> loadPinnedRoots() {
        try (InputStream in = AndroidKeyAttestationVerifierAdapter.class.getResourceAsStream(ROOTS_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("missing resource " + ROOTS_RESOURCE);
            }
            Collection<? extends java.security.cert.Certificate> certs =
                    CertificateFactory.getInstance("X.509").generateCertificates(in);
            List<X509Certificate> out = new ArrayList<>();
            for (java.security.cert.Certificate c : certs) {
                out.add((X509Certificate) c);
            }
            if (out.isEmpty()) {
                throw new IllegalStateException("no pinned attestation roots in " + ROOTS_RESOURCE);
            }
            return out;
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("cannot load pinned attestation roots", e);
        }
    }

    static Set<String> splitCsv(String csv, boolean lower) {
        Set<String> out = new LinkedHashSet<>();
        if (csv == null) {
            return out;
        }
        for (String raw : csv.split(",")) {
            String t = raw.trim();
            if (!t.isEmpty()) {
                out.add(lower ? t.toLowerCase(Locale.ROOT) : t);
            }
        }
        return out;
    }

    /**
     * Accepts signing-cert SHA-256 digests as hex (with or without ':' separators,
     * any case, as printed by {@code apksigner}/{@code keytool}) or base64, and
     * normalizes them to lowercase hex. Malformed entries are skipped with a warning.
     */
    static Set<String> normalizeDigests(Set<String> raw) {
        Set<String> out = new LinkedHashSet<>();
        for (String r : raw) {
            String hex = r.replace(":", "").toLowerCase(Locale.ROOT);
            if (hex.matches("[0-9a-f]{64}")) {
                out.add(hex);
                continue;
            }
            try {
                byte[] b = java.util.Base64.getDecoder().decode(r.replace('-', '+').replace('_', '/'));
                if (b.length == 32) {
                    out.add(HexFormat.of().formatHex(b));
                    continue;
                }
            } catch (IllegalArgumentException ignored) {
                // fall through
            }
            log.warn("Ignoring malformed signing-cert SHA-256 in app.auth.attestation.android.signing-cert-sha256");
        }
        return out;
    }
}
