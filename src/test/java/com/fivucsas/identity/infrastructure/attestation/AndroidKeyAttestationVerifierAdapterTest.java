package com.fivucsas.identity.infrastructure.attestation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.DeviceAttestationVerifierPort.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Android Key Attestation verifier tests: REAL device chains published in
 * {@code android/keyattestation} testdata (Apache-2.0, see the NOTICE next to the
 * fixtures) against the REAL pinned Google roots, plus synthetic chains for the
 * negative paths a real chain cannot express.
 */
@DisplayName("AndroidKeyAttestationVerifierAdapter")
class AndroidKeyAttestationVerifierAdapterTest {

    private static final String SAMPLES = "/attestation/keyattestation-samples/";
    private static final ObjectMapper JSON = new ObjectMapper();

    // ------------------------------------------------------------------ helpers

    record Sample(List<byte[]> chain, byte[] challenge, String packageName, String digestHex, Instant created) {
    }

    static Sample sample(String name) throws Exception {
        List<byte[]> chain = new ArrayList<>();
        try (InputStream in = AndroidKeyAttestationVerifierAdapterTest.class.getResourceAsStream(SAMPLES + name + ".pem")) {
            for (var c : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                chain.add(c.getEncoded());
            }
        }
        JsonNode j;
        try (InputStream in = AndroidKeyAttestationVerifierAdapterTest.class.getResourceAsStream(SAMPLES + name + ".json")) {
            j = in == null ? null : JSON.readTree(in);
        }
        if (j == null) {
            return new Sample(chain, new byte[0], null, null, null);
        }
        JsonNode app = j.path("softwareEnforced").path("attestationApplicationId");
        return new Sample(chain,
                Base64.getDecoder().decode(j.get("attestationChallenge").asText()),
                app.path("packages").get(0).path("name").asText(),
                HexFormat.of().formatHex(Base64.getDecoder().decode(app.path("signatures").get(0).asText())),
                Instant.ofEpochMilli(j.path("softwareEnforced").path("creationDateTime").asLong()));
    }

    static AndroidKeyAttestationVerifierAdapter.Settings settings(String pkg, String digest, boolean strongBox,
                                                                  boolean verifiedBoot, boolean locked,
                                                                  boolean failOpen) {
        return new AndroidKeyAttestationVerifierAdapter.Settings(Set.of(pkg), Set.of(digest), strongBox,
                verifiedBoot, locked, true, failOpen, Duration.ofMinutes(5));
    }

    static GoogleAttestationStatusList statusList(Supplier<String> body, Instant at) {
        return new GoogleAttestationStatusList(body, Duration.ofHours(1), Duration.ofHours(24),
                Clock.fixed(at, ZoneOffset.UTC));
    }

    static final Supplier<String> EMPTY_LIST = () -> "{\"entries\":{}}";

    static AndroidKeyAttestationVerifierAdapter realRoots(AndroidKeyAttestationVerifierAdapter.Settings s,
                                                          Supplier<String> list, Instant at) {
        return new AndroidKeyAttestationVerifierAdapter(AndroidKeyAttestationVerifierAdapter.loadPinnedRoots(), s,
                statusList(list, at), Clock.fixed(at, ZoneOffset.UTC));
    }

    static AndroidKeyAttestationVerifierAdapter forSample(Sample s, Instant at) {
        return realRoots(settings(s.packageName(), s.digestHex(), false, true, true, false), EMPTY_LIST, at);
    }

    // ------------------------------------------------------------------ real chains

    @Nested
    @DisplayName("real device chains (android/keyattestation testdata)")
    class RealChains {

        @Test
        void pixel9ProTeeRkpChainVerifies() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            Result r = forSample(s, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge());
            assertThat(r.valid()).as(r.reason()).isTrue();
            assertThat(r.securityLevel()).isEqualTo("TRUSTED_ENVIRONMENT");
            assertThat(r.packageName()).isEqualTo("com.google.android.attestation");
            assertThat(r.verifiedBootState()).isEqualTo("VERIFIED");
            assertThat(r.deviceLocked()).isTrue();
            assertThat(r.attestedPublicKey().getAlgorithm()).isEqualTo("EC");
        }

        @Test
        void strongBoxChainsVerifyIncludingTheNew2025EcRoot() throws Exception {
            for (String name : List.of("caiman_sdk36_SB_EC_RKP", "tegu_sdk36_SB_EC_2026_ROOT")) {
                Sample s = sample(name);
                AndroidKeyAttestationVerifierAdapter v = realRoots(
                        settings(s.packageName(), s.digestHex(), true, true, true, false), EMPTY_LIST, s.created());
                Result r = v.verifyAndroidKeyAttestation(s.chain(), s.challenge());
                assertThat(r.valid()).as(name + ": " + r.reason()).isTrue();
                assertThat(r.securityLevel()).isEqualTo("STRONG_BOX");
            }
        }

        @Test
        void teeChainRejectedWhenStrongBoxRequired() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            Result r = realRoots(settings(s.packageName(), s.digestHex(), true, true, true, false), EMPTY_LIST,
                    s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge());
            assertThat(r.reason()).isEqualTo("STRONGBOX_REQUIRED");
        }

        @Test
        void challengeMustMatchTheIssuedNonce() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            byte[] other = s.challenge().clone();
            other[0] ^= 1;
            assertThat(forSample(s, s.created()).verifyAndroidKeyAttestation(s.chain(), other).reason())
                    .isEqualTo("CHALLENGE_MISMATCH");
        }

        @Test
        void packageAndSigningCertAreEnforced() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            assertThat(realRoots(settings("com.fivucsas.mobile", s.digestHex(), false, true, true, false),
                    EMPTY_LIST, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge()).reason())
                    .isEqualTo("APP_PACKAGE_NOT_ALLOWED");
            assertThat(realRoots(settings(s.packageName(), "00".repeat(32), false, true, true, false),
                    EMPTY_LIST, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge()).reason())
                    .isEqualTo("APP_SIGNATURE_NOT_ALLOWED");
        }

        @Test
        void rkpIntermediatesExpireAndAreRejectedLater() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            Instant later = s.created().plus(Duration.ofDays(400));
            assertThat(forSample(s, later).verifyAndroidKeyAttestation(s.chain(), s.challenge()).reason())
                    .isEqualTo("CERT_EXPIRED");
        }

        @Test
        void expiredFactoryChainToleratedButUnlockedBootloaderRejected() throws Exception {
            // walleye: factory-provisioned, intermediates expired 2026-05, key created 2026-08,
            // device UNLOCKED / UNVERIFIED.
            Sample s = sample("walleye_sdk27_TEE_EC_NONE");
            assertThat(forSample(s, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge()).reason())
                    .isEqualTo("BOOT_STATE_NOT_VERIFIED");
            Result relaxed = realRoots(settings(s.packageName(), s.digestHex(), false, false, false, false),
                    EMPTY_LIST, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge());
            assertThat(relaxed.valid()).as(relaxed.reason()).isTrue();
            assertThat(relaxed.deviceLocked()).isFalse();
            Result lockedOnly = realRoots(settings(s.packageName(), s.digestHex(), false, false, true, false),
                    EMPTY_LIST, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge());
            assertThat(lockedOnly.reason()).isEqualTo("DEVICE_UNLOCKED");
        }

        @Test
        void softwareSecurityLevelRejected() throws Exception {
            Sample s = sample("marlin_sdk29_TEE_EC_NONE");
            Result r = realRoots(settings(s.packageName(), s.digestHex(), false, false, false, false),
                    EMPTY_LIST, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge());
            assertThat(r.valid()).isFalse();
            assertThat(r.reason()).isIn("SOFTWARE_SECURITY_LEVEL", "UNTRUSTED_ROOT");
        }

        @Test
        void rsaLeafRejected() throws Exception {
            Sample s = sample("akita_sdk34_TEE_RSA_NONE");
            Result r = realRoots(settings(s.packageName(), s.digestHex(), false, false, false, false),
                    EMPTY_LIST, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge());
            assertThat(r.reason()).isEqualTo("KEY_NOT_EC_P256");
        }

        @Test
        void revokedSerialRejectedAndStatusListFailPolicy() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            X509Certificate leafIssuer = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(s.chain().get(1)));
            String serial = leafIssuer.getSerialNumber().toString(16);
            AndroidKeyAttestationVerifierAdapter.Settings st =
                    settings(s.packageName(), s.digestHex(), false, true, true, false);
            Supplier<String> revoked = () -> "{\"entries\":{\"" + serial.toUpperCase()
                    + "\":{\"status\":\"REVOKED\",\"reason\":\"KEY_COMPROMISE\"}}}";
            assertThat(realRoots(st, revoked, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge())
                    .reason()).isEqualTo("CERT_REVOKED");

            Supplier<String> down = () -> {
                throw new IllegalStateException("unreachable");
            };
            assertThat(realRoots(st, down, s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge())
                    .reason()).isEqualTo("REVOCATION_STATUS_UNAVAILABLE");
            assertThat(realRoots(settings(s.packageName(), s.digestHex(), false, true, true, true), down,
                    s.created()).verifyAndroidKeyAttestation(s.chain(), s.challenge()).valid()).isTrue();
        }

        @Test
        void chainWithoutTheRootStillAnchorsToPinnedRoot() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            List<byte[]> noRoot = s.chain().subList(0, s.chain().size() - 1);
            assertThat(forSample(s, s.created()).verifyAndroidKeyAttestation(noRoot, s.challenge()).valid())
                    .isTrue();
        }

        @Test
        void droppedIntermediateBreaksNameChaining() throws Exception {
            Sample s = sample("caiman_sdk36_TEE_EC_RKP");
            List<byte[]> broken = new ArrayList<>(s.chain());
            broken.remove(2);
            assertThat(forSample(s, s.created()).verifyAndroidKeyAttestation(broken, s.challenge()).valid())
                    .isFalse();
        }

        @Test
        void malformedKeyDescriptionsRejected() throws Exception {
            for (String name : List.of("invalid_malformed_rot_device_locked", "invalid_tags_not_in_ascending_order")) {
                Sample s = sample(name);
                X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(s.chain().get(0)));
                org.assertj.core.api.Assertions.assertThatThrownBy(() -> {
                    AndroidKeyDescription kd = AndroidKeyDescription.parse(leaf);
                    kd.hardwareEnforced().rootOfTrust();
                }).as(name).isInstanceOf(Der.DerException.class);
            }
        }

        @Test
        void parsesEveryValidSample() throws Exception {
            for (String name : List.of("caiman_sdk36_TEE_EC_RKP", "caiman_sdk36_SB_EC_RKP",
                    "tegu_sdk36_SB_EC_2026_ROOT", "frankel_sdk37_TEE_EC_2026", "walleye_sdk27_TEE_EC_NONE",
                    "sony-xperia10-iii_sdk33_TEE_EC", "akita_sdk34_TEE_EC_NONE", "akita_sdk34_TEE_RSA_NONE")) {
                Sample s = sample(name);
                X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(s.chain().get(0)));
                AndroidKeyDescription kd = AndroidKeyDescription.parse(leaf);
                assertThat(kd.attestationChallenge()).as(name).isEqualTo(s.challenge());
                AndroidKeyDescription.ApplicationId app = kd.softwareEnforced().applicationId();
                assertThat(app.packageNames()).as(name).contains(s.packageName());
                assertThat(HexFormat.of().formatHex(app.signatureDigests().get(0))).isEqualTo(s.digestHex());
                assertThat(kd.hardwareEnforced().rootOfTrust()).as(name).isNotNull();
            }
        }
    }

    // ------------------------------------------------------------------ synthetic chains

    @Nested
    @DisplayName("synthetic chains (test root)")
    class SyntheticChains {

        final Instant now = Instant.parse("2026-11-02T10:00:00Z");
        final byte[] nonce = HexFormat.of().parseHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        final byte[] digest = new byte[32];

        TestAttestationChains.Kd kd() {
            TestAttestationChains.Kd kd = new TestAttestationChains.Kd();
            kd.challenge = nonce;
            kd.signingCertDigest = digest;
            return kd;
        }

        AndroidKeyAttestationVerifierAdapter verifier(TestAttestationChains.Chain c) {
            return new AndroidKeyAttestationVerifierAdapter(List.of(c.rootCert()),
                    settings("com.fivucsas.mobile", HexFormat.of().formatHex(digest), false, true, true, false),
                    statusList(EMPTY_LIST, now), Clock.fixed(now, ZoneOffset.UTC));
        }

        @Test
        void validChainVerifiesAndReturnsTheLeafKey() {
            TestAttestationChains.Chain c = TestAttestationChains.chain(kd(), now);
            Result r = verifier(c).verifyAndroidKeyAttestation(c.der(), nonce);
            assertThat(r.valid()).as(r.reason()).isTrue();
            assertThat(r.attestedPublicKey()).isEqualTo(c.leaf().getPublic());
        }

        @Test
        void untrustedRootRejectedByRealPins() {
            TestAttestationChains.Chain c = TestAttestationChains.chain(kd(), now);
            AndroidKeyAttestationVerifierAdapter real = realRoots(
                    settings("com.fivucsas.mobile", HexFormat.of().formatHex(digest), false, true, true, false),
                    EMPTY_LIST, now);
            assertThat(real.verifyAndroidKeyAttestation(c.der(), nonce).reason()).isEqualTo("UNTRUSTED_ROOT");
        }

        @Test
        void keyPropertyChecks() {
            TestAttestationChains.Kd soft = kd();
            soft.attestationSecurityLevel = 0;
            soft.keyMintSecurityLevel = 0;
            TestAttestationChains.Kd imported = kd();
            imported.origin = 2;
            TestAttestationChains.Kd encrypt = kd();
            encrypt.purpose = 0;
            TestAttestationChains.Kd noRot = kd();
            noRot.emitRootOfTrust = false;
            TestAttestationChains.Kd unordered = kd();
            unordered.swapTagOrder = true;
            TestAttestationChains.Kd failedBoot = kd();
            failedBoot.verifiedBootState = 3;
            for (var e : List.of(
                    java.util.Map.entry(soft, "SOFTWARE_SECURITY_LEVEL"),
                    java.util.Map.entry(imported, "KEY_NOT_GENERATED_IN_HARDWARE"),
                    java.util.Map.entry(encrypt, "KEY_PURPOSE_NOT_SIGN"),
                    java.util.Map.entry(noRot, "ROOT_OF_TRUST_MISSING"),
                    java.util.Map.entry(unordered, "KEY_DESCRIPTION_INVALID"),
                    java.util.Map.entry(failedBoot, "BOOT_STATE_NOT_VERIFIED"))) {
                TestAttestationChains.Chain c = TestAttestationChains.chain(e.getKey(), now);
                assertThat(verifier(c).verifyAndroidKeyAttestation(c.der(), nonce).reason())
                        .isEqualTo(e.getValue());
            }
        }

        @Test
        void chainExtendedWithAFakeCertSignedByAnAttestedKeyIsRejected() {
            // Attack: a genuinely attested key (any challenge) signs a forged leaf
            // carrying a KeyDescription with the server nonce. Only the leaf may
            // carry the extension, so the genuine cert in position 1 gives it away.
            TestAttestationChains.Kd genuine = kd();
            genuine.challenge = new byte[32];
            TestAttestationChains.Chain c = TestAttestationChains.chain(genuine, now);
            KeyPair attacker = TestAttestationChains.ecKeyPair("secp256r1");
            X509Certificate forged = TestAttestationChains.cert(
                    TestAttestationChains.name("Forged", null), TestAttestationChains.name("Android Keystore Key", null),
                    attacker.getPublic(), c.leaf().getPrivate(), Instant.EPOCH,
                    Instant.parse("2048-01-01T00:00:00Z"), 7, kd().encode(), false);
            List<byte[]> chain = List.of(TestAttestationChains.encoded(forged), c.der().get(0), c.der().get(1),
                    c.der().get(2));
            assertThat(verifier(c).verifyAndroidKeyAttestation(chain, nonce).reason())
                    .isEqualTo("EXTRA_ATTESTATION_EXTENSION");
        }

        @Test
        void tamperedLeafSignatureRejected() {
            TestAttestationChains.Chain c = TestAttestationChains.chain(kd(), now);
            byte[] leaf = c.der().get(0).clone();
            leaf[leaf.length - 5] ^= 0x01;
            Result r = verifier(c).verifyAndroidKeyAttestation(List.of(leaf, c.der().get(1), c.der().get(2)), nonce);
            assertThat(r.valid()).isFalse();
        }

        @Test
        void garbageAndEmptyInputFailClosed() {
            TestAttestationChains.Chain c = TestAttestationChains.chain(kd(), now);
            AndroidKeyAttestationVerifierAdapter v = verifier(c);
            assertThat(v.verifyAndroidKeyAttestation(List.of(new byte[]{1, 2, 3}), nonce).reason())
                    .isEqualTo("CHAIN_PARSE_ERROR");
            assertThat(v.verifyAndroidKeyAttestation(List.of(), nonce).reason()).isEqualTo("MISSING_INPUT");
            assertThat(v.verifyAndroidKeyAttestation(c.der(), null).reason()).isEqualTo("MISSING_INPUT");
        }
    }

    @Test
    @DisplayName("signing-cert digest config accepts hex with colons and base64, skips garbage")
    void digestNormalization() {
        byte[] raw = Base64.getDecoder().decode("EDk47kU35Z6O55L2VFBPuDRvxrNG0LvEQV/DOfz8jsE=");
        String hex = HexFormat.of().formatHex(raw);
        StringBuilder colons = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            colons.append(i == 0 ? "" : ":").append(hex.substring(i, i + 2).toUpperCase());
        }
        assertThat(AndroidKeyAttestationVerifierAdapter.normalizeDigests(
                Set.of("EDk47kU35Z6O55L2VFBPuDRvxrNG0LvEQV/DOfz8jsE=")))
                .containsExactly(hex);
        assertThat(AndroidKeyAttestationVerifierAdapter.normalizeDigests(Set.of(colons.toString())))
                .containsExactly(hex);
        assertThat(AndroidKeyAttestationVerifierAdapter.normalizeDigests(Set.of("nonsense"))).isEmpty();
    }
}
