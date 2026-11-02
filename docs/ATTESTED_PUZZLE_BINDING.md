# Attested puzzle binding (Android Key Attestation)

Status: implemented server-side behind `app.auth.attested-binding` (default **OFF**);
Android attestation + signing layer implemented in client-apps; the Android
puzzle/embedding **capture UI does not exist yet** (see §9). Not yet exercised on a
real device.

Related: biometric-processor `CLAUDE.md` ("Puzzle liveness session", "Contract v2"),
web-app `CLAUDE.md` (puzzle section), `PuzzleVerifyMfaStepHandler`.

## 1. Problem

A PUZZLE step with `puzzleConfig.alsoMatchFaceIdentity` proves two things in one
step: liveness (bio re-scores the landmark trace, contract v2) and identity (the
client's 512-d Facenet embedding matches the enrolled template). Nothing ties the
two together. An attacker can perform the puzzle live with their own face and
submit a victim's embedding (split capture). The contract-v2 "binding-frame
consistency check" only compares client-declared data with client-declared data,
so a modified client passes it.

In a browser no cryptography can close this gap: the attacker controls the code
that would hold any key. On Android it can be closed with hardware-backed **key
attestation**: a key generated inside the TEE or StrongBox with
`setAttestationChallenge(nonce)` comes with an X.509 chain rooted at Google's
hardware attestation root whose KeyDescription extension
(OID `1.3.6.1.4.1.11129.2.1.17`) is written by the secure hardware and states the
challenge, the calling app (package name + signing-certificate SHA-256), the
security level and the device's verified-boot state. If that key signs the
(embedding, trace) pair, the server learns that the genuine, unmodified FIVUCSAS
app on a genuine, locked device produced both within this server-issued session.

## 2. Threat model

### Stops

| Attack | Why it fails |
|---|---|
| Modified / repackaged client (patched APK, Frida-instrumented re-signed APK) | `attestationApplicationId` carries the signing-cert digest of the calling app, written by the OS/TEE. A re-signed APK has a different digest → `APP_SIGNATURE_NOT_ALLOWED`. |
| Software-only key / emulator | KeyDescription security level SOFTWARE, or a chain not rooted at a pinned Google root → `SOFTWARE_SECURITY_LEVEL` / `UNTRUSTED_ROOT`. |
| Split capture via a different app or device (puzzle done live, embedding from elsewhere) | The server matches **exactly** the embedding the attested key signed, and the signature also covers the digest of the traces bio accepted. Substituting either breaks the signature (`BINDING_SIGNATURE_INVALID`). The genuine app only signs what its own capture pipeline produced. |
| Replay across sessions / devices | The nonce is 32 random bytes, single-use (GETDEL), bound to the MFA session and the bio puzzle session, TTL 300 s. It is inside the hardware-written KeyDescription and inside the signed payload → `CHALLENGE_MISMATCH` / `CHALLENGE_NOT_ISSUED_OR_USED` / `CHALLENGE_SESSION_MISMATCH`. |
| Chain extension (an attested key used as a CA to sign a forged leaf with a fake KeyDescription) | Only the leaf may carry a KeyDescription (`EXTRA_ATTESTATION_EXTENSION`), mirroring Google's reference verifier. |
| Unlocked bootloader / custom ROM | RootOfTrust `verifiedBootState != VERIFIED` or `deviceLocked == false` → rejected (both configurable). |
| Leaked attestation keys that Google has revoked | Every certificate serial is checked against Google's status list → `CERT_REVOKED`. |
| Imported (not hardware-generated) key | `origin != GENERATED` → `KEY_NOT_GENERATED_IN_HARDWARE`. |

### Does NOT stop (documented residual risk)

* **Leaked, not-yet-revoked keybox** on a rooted device ("keybox spoofing" modules
  that make a rooted device present a genuine-looking TEE chain). Mitigation is
  only revocation-list freshness and, later, Play Integrity "strong" verdicts.
* **Camera injection at the HAL / virtual camera** on a device that still passes
  attestation: the genuine app faithfully processes frames that are not from the
  physical sensor. Attestation proves *which code* ran, not *what the sensor saw*.
* **Deepfake rendered into the genuine camera pipeline** (e.g. a screen or
  projector in front of the camera, or a compromised camera driver): the PUZZLE
  liveness thresholds and the passive PAD are the controls here, not attestation.
* **Compromise of the TEE itself** (StrongBox reduces this; `require-strongbox`).
* The **web** path: browsers cannot attest. With the policy on, a bound PUZZLE step
  from the web fails closed. Enable per tenant only where the bound puzzle runs in
  the native app.

## 3. Components

| Layer | Component |
|---|---|
| bio | `puzzle_trace_digest.py` (canonical trace digest), `PuzzleSessionManager.verdict_with_trace_digest`, verdict request `include_trace_digest` → response `trace_digest` (only when requested; flag-OFF/web wire unchanged) |
| identity (application) | `AttestedBindingPolicy`, `AttestationChallengeIssuer`, `AttestedBindingPayload`, `AttestedPuzzleBindingVerifier`, ports `DeviceAttestationVerifierPort` + `AttestationChallengePort`, `PuzzleVerifyMfaStepHandler` (attested branch) |
| identity (infrastructure) | `AndroidKeyAttestationVerifierAdapter`, `AndroidKeyDescription` + `Der` (strict DER parser, no BouncyCastle), `GoogleAttestationStatusList` (cached revocation), `RedisAttestationChallengeAdapter`, pinned roots `resources/attestation/google-hardware-attestation-roots.pem` |
| client-apps | `shared/.../attestation/` commonMain contract (`AttestedKeyProvider` expect/actual, `AttestedBindingPayload`, `PuzzleTraceDigest`, pure-Kotlin `Sha256`), `androidMain` `AttestedKeyManager` (AndroidKeyStore), desktop/iOS actuals = unsupported |

## 4. Protocol

### 4.1 Nonce issuance (CREATE)

`POST /api/v1/auth/mfa/puzzle/session {sessionToken}` (existing endpoint). When
`AttestedBindingPolicy` is on for the session's tenant **and** the step has
`alsoMatchFaceIdentity`, identity:

1. creates the bio session as today (owner, policy, create cap, contract record);
2. generates 32 bytes from `SecureRandom`;
3. stores `mfa:puzzle:attest:<bioSessionId> = <mfaSessionId>|<base64 nonce>` in
   Redis with TTL 300 s (= bio puzzle session TTL). Store down → 503 (fail closed);
4. returns bio's response plus
   `"attestation_challenge": "<base64url, no padding>"` and
   `"attestation_payload_version": 1`.

Policy off ⇒ the response is bio's, verbatim (unchanged).

### 4.2 Client (Android)

1. Generate an EC P-256 key in AndroidKeyStore: `PURPOSE_SIGN`, `DIGEST_SHA256`,
   `setAttestationChallenge(nonce)`, `setUserAuthenticationRequired(false)`,
   StrongBox when available (`FEATURE_STRONGBOX_KEYSTORE`, fallback TEE on
   `StrongBoxUnavailableException`). Alias is random per session.
2. Run the puzzle: SUBMIT each challenge's v2 trace through
   `/auth/mfa/puzzle/session/{id}/challenge`. Keep the traces bio **accepted**
   (`verified:true`), in issued order.
3. Compute the 512-d embedding from a frame of the same capture and the binding
   frame (`{t, f[96]}`) exactly as the web client does.
4. Compute `trace_digest` (§4.4), build the canonical payload (§4.3), sign it with
   `SHA256withECDSA`, export the certificate chain, **delete the key**.
5. `POST /auth/mfa/step` with method `PUZZLE` and data:

```json
{
  "puzzle_session_id": "<bio session id>",
  "embedding": [512 doubles],
  "binding_frame": {"t": 1234, "f": [96 ints]},
  "attestation": {
    "format": "android-key",
    "payload_version": 1,
    "certificate_chain": ["<base64 DER leaf>", "...", "<base64 DER root>"],
    "signature": "<base64 DER ECDSA>",
    "trace_digest": "<64 hex, optional, diagnostics>"
  }
}
```

### 4.3 Canonical payload (version 1)

Big-endian throughout; signature = ECDSA P-256 / SHA-256 (JCA `SHA256withECDSA`,
ASN.1 DER) by the attested key.

```
"FIVUCSAS-PUZZLE-BINDING-V1"          26 ASCII bytes
u32 len || puzzle_session_id          UTF-8
u32 len || nonce                      raw (32 bytes)
u32 n   || n x f64                    embedding, IEEE-754 binary64
trace_digest                          32 raw bytes
i64 t   || u32 n || n x i32           binding frame (96 ints)
```

The embedding is encoded from the doubles that are sent in the JSON (a float
embedding is widened to `Double` once, before both). `Double.toString` (used by
kotlinx.serialization) always round-trips exactly and Jackson parses decimal
literals with correct rounding, so both sides encode bit-identical values. The server builds the payload from **the same
`List<Double>` it then forwards to bio's `/verify-embedding`**.

Golden vector (pinned in identity `AttestedBindingPayloadTest`, client-apps
`AttestedBindingPayloadTest`, recomputed independently in Python): session
`"puzzle-session-1"`, nonce `00 01 .. 1f`, embedding
`[0.1, -0.25, 1/3, 0.0, -0.0, 1e-7]`, trace digest
`8843a760…193364c`, `t = 1234567`, `f[i] = 3i - 100` → 562 bytes,
SHA-256 `26b536124412eac9347ea789a73bda97a3406b7e5cddb55c2fbe5cfdf538e9f7`.

### 4.4 Trace digest

Per accepted challenge (`FPT1`): `"FPT1" || u8 len(action) || action ||
i32 version || i32 frame_width || i32 frame_height || u32 frames ||
per frame: i64 t || u8 mask(bit0 f, bit1 h) || 96 x i32 f? || 63 x i32 h?`,
`challenge_digest = SHA-256(...)`.
Session: `trace_digest = hex(SHA-256("FPS1" || u32 n || challenge_digest[0..n-1]))`
over the accepted challenges in issued order. bio computes it from the trace it
actually scored (rejected attempts are excluded) and returns it on a passing v2
verdict when identity sends `include_trace_digest: true`. Golden vector in bio
`test_puzzle_trace_digest.py` and client-apps `PuzzleTraceDigestTest`.

### 4.5 Server verification (`PuzzleVerifyMfaStepHandler`)

Only when binding is required (`alsoMatchFaceIdentity` + client-side-embedding
policy) **and** `AttestedBindingPolicy` is on for the tenant. Before the
consuming verdict:

1. Consume the nonce (GETDEL), whatever happens next.
2. Session must be contract v2 with a valid binding frame (`TRACE_CONTRACT_NOT_V2`).
3. Nonce exists (`CHALLENGE_NOT_ISSUED_OR_USED`) and was issued to this MFA session
   (`CHALLENGE_SESSION_MISMATCH`).
4. Bundle well-formed (`ATTESTATION_MISSING_OR_MALFORMED`; ≤ 10 certs, ≤ 16 KiB
   each, signature ≤ 256 bytes, format `android-key`, version 1); embedding has 512
   numbers (`EMBEDDING_INVALID`).
5. Device attestation (`DeviceAttestationVerifierPort`, §5).

Any failure above fails the step **and consumes the bio session** (plain verdict).
Then:

6. bio verdict with `require_identity_binding` + `binding_frame` +
   `include_trace_digest`; must be `verified:true` and `binding_checked:true`.
7. bio `trace_digest` present (`TRACE_DIGEST_MISSING`); equals the client's
   diagnostic digest when supplied (`TRACE_DIGEST_MISMATCH`).
8. ECDSA signature by the attested leaf key over the canonical payload built from
   the bio session id, the nonce, the embedding, bio's trace digest and the
   sanitized binding frame (`BINDING_SIGNATURE_INVALID`).
9. pgvector match of that exact embedding against the server user's template.

Every rejection is logged as `AUDIT: PUZZLE attested binding failed — reason=<CODE>`.

## 5. Android attestation checks (`AndroidKeyAttestationVerifierAdapter`)

1. Parse the chain (X.509). Anchor: the last certificate's SubjectPublicKeyInfo is
   one of the pinned Google roots, or the last certificate is issued and signed by a
   pinned root (chain sent without the root). Pinned: the RSA-4096 root (key shared
   by the 2016/2019/2022 certificates) and the 2025 ECDSA P-384
   "Key Attestation CA1" root. `UNTRUSTED_ROOT` otherwise.
2. Root → leaf: issuer/subject name chaining, each signature verified with the
   issuer key, validity of every certificate except the leaf (device-set validity,
   as in Google's verifier) with `clock-skew` tolerance for not-yet-valid; an
   expired **factory-provisioned** chain (the cert below the root has a
   serialNumber RDN) is tolerated exactly like Google's verifier, RKP chains must
   be in validity.
3. Only the leaf carries a KeyDescription.
4. Revocation (§6).
5. KeyDescription (strict DER: definite minimal lengths, DER booleans,
   AuthorizationList tags strictly ascending):
   * `attestationChallenge == nonce` (constant-time compare);
   * effective security level = min(attestation, KeyMint) ≥ TEE; StrongBox when
     `require-strongbox`; for RKP chains the attestation certificate's `O=` must
     say `TEE` / `StrongBox` consistently;
   * hardware-enforced `origin == GENERATED`, purposes ∋ SIGN, algorithm EC, curve
     P-256 (when present), and the leaf public key really is P-256;
   * hardware-enforced RootOfTrust present; `verifiedBootState == VERIFIED`
     (`require-verified-boot`), `deviceLocked == true` (`require-device-locked`);
   * `attestationApplicationId`: every listed package is allowed and every listed
     signing-cert digest is in the configured list (exact SHA-256 match).

Failure codes: `MISSING_INPUT`, `NOT_CONFIGURED`, `CHAIN_PARSE_ERROR`,
`UNTRUSTED_ROOT`, `CHAIN_TOO_SHORT`, `NAME_CHAINING`, `BAD_CERT_SIGNATURE`,
`CERT_NOT_YET_VALID`, `CERT_EXPIRED`, `EXTRA_ATTESTATION_EXTENSION`,
`REVOCATION_STATUS_UNAVAILABLE`, `CERT_REVOKED`, `KEY_DESCRIPTION_INVALID`,
`CHALLENGE_MISMATCH`, `SOFTWARE_SECURITY_LEVEL`, `STRONGBOX_REQUIRED`,
`SECURITY_LEVEL_CHAIN_MISMATCH`, `KEY_NOT_GENERATED_IN_HARDWARE`,
`KEY_PURPOSE_NOT_SIGN`, `KEY_NOT_EC_P256`, `ROOT_OF_TRUST_MISSING`,
`BOOT_STATE_NOT_VERIFIED`, `DEVICE_UNLOCKED`, `APP_ID_MISSING`,
`APP_PACKAGE_NOT_ALLOWED`, `APP_SIGNATURE_NOT_ALLOWED`, `VERIFICATION_ERROR`.

## 6. Revocation

`https://android.googleapis.com/attestation/status` (JSON `{"entries": {"<serial
hex, lowercase, no leading zeros>": {"status": "REVOKED"|"SUSPENDED", "reason":
…}}}`; Google serves it with `max-age=86400`). Fetched lazily on first use with a
5 s timeout, cached for `cache-ttl` (default 1 h); after a failed refresh the
stale copy is used up to `max-stale` (default 24 h). With no usable list:
`fail-policy=closed` (default) rejects (`REVOCATION_STATUS_UNAVAILABLE`), `open`
accepts with a warning. Every certificate in the submitted chain, including the
root, is checked.

## 7. Configuration

| Property (env) | Default | Meaning |
|---|---|---|
| `app.auth.attested-binding` (`APP_AUTH_ATTESTED_BINDING`) | `false` | Master switch |
| `app.auth.attested-binding-tenants` (`APP_AUTH_ATTESTED_BINDING_TENANTS`) | empty | Per-tenant canary (UUID CSV) |
| `app.auth.attestation.android.package` | `com.fivucsas.mobile` | Allowed applicationId(s), CSV |
| `app.auth.attestation.android.signing-cert-sha256` | **empty ⇒ reject all** | Release signing-cert SHA-256 (hex, `:` allowed, or base64), CSV |
| `app.auth.attestation.android.require-strongbox` | `false` | Require StrongBox |
| `app.auth.attestation.android.require-verified-boot` | `true` | Require `VERIFIED` |
| `app.auth.attestation.android.require-device-locked` | `true` | Require locked bootloader |
| `app.auth.attestation.android.clock-skew` | `PT5M` | Not-yet-valid tolerance |
| `app.auth.attestation.android.revocation.enabled` | `true` | Check the status list |
| `app.auth.attestation.android.revocation.url` | Google URL | Status list URL |
| `app.auth.attestation.android.revocation.cache-ttl` | `PT1H` | Refresh interval |
| `app.auth.attestation.android.revocation.max-stale` | `PT24H` | Stale grace |
| `app.auth.attestation.android.revocation.fail-policy` | `closed` | `closed` / `open` |

The prod compose `environment:` block forwards the switch, canary, package,
digest, StrongBox and fail-policy variables.

Getting the digest of the release key: `apksigner verify --print-certs
fivucsas-release.apk` (line `Signer #1 certificate SHA-256 digest`) or
`keytool -list -v -keystore keystore/<release>.jks`. If the app is distributed
through Play with Play App Signing, use the **app signing key** digest from the
Play Console, not the upload key.

## 8. Rollout

1. Deploy bio (verdict `include_trace_digest`; inert unless requested) and identity
   with the flag OFF. Nothing changes on the wire.
2. Set `APP_AUTH_ATTESTATION_ANDROID_SIGNING_CERT_SHA256` to the release digest.
3. Ship an app build with the attested puzzle capture (§9).
4. Canary: `APP_AUTH_ATTESTED_BINDING_TENANTS=<tenant uuid>` for a tenant whose
   bound PUZZLE step is used from the app, with bio `PUZZLE_TRACE_V2_ENABLED=true`
   and identity `APP_AUTH_CLIENT_SIDE_EMBEDDING` on for that tenant.
5. Watch `AUDIT: PUZZLE attested binding failed — reason=…` and
   `PUZZLE device attestation ok — level=…`. Revert = unset the env var (no
   rebuild).

## 9. Client status and remaining work

The Android app today has **no** server-session puzzle and **no** on-device
embedding: `FaceLivenessScreen`/`LivenessViewModel` run a local, client-scored
challenge list (manually advanced) and upload one JPEG to the passive liveness
endpoint; the stack is CameraX + ML Kit face detection (no MediaPipe face mesh, no
Facenet, no ONNX Runtime / TFLite). Implemented now: the attestation and signing
layer and the wire contract (`AttestedKeyManager`, payload, trace digest, request
DTOs, puzzle-session API calls). Still to build (tracked as a TODO in
`shared/.../attestation/AttestedPuzzleCapture.kt`):

* MediaPipe Tasks FaceLandmarker (Android) at ≤ 25 fps, emitting the 32 trace
  landmarks in `trace_face_indices` order (ints, 1e-4 units), and HandLandmarker
  for hand challenges, mirroring web `PuzzleTraceRecorder`;
* challenge engine parity with web `BiometricPuzzle` (baseline-relative gates,
  return-to-centre tail, frame-interval rules), ideally driven by the same golden
  contract traces;
* Facenet512 on device (ONNX Runtime Android, the same FP16 model as the web, with
  the web's aligner + BGR [0,1] preprocessing), from the best frontal frame of the
  same capture;
* the capture UI and wiring into the MFA flow (`PUZZLE` step).

## 10. iOS: App Attest (later twin)

`DCAppAttestService` gives the same shape: `generateKey()` +
`attestKey(keyId, clientDataHash: SHA256(nonce))` returns a CBOR attestation
statement whose x5c chain roots at Apple's App Attest root and whose authData
carries the App ID (`teamId.bundleId`) RP-ID hash and a counter; later
`generateAssertion(keyId, clientDataHash: SHA256(payload))` signs the canonical
payload. Server work: a second adapter behind `DeviceAttestationVerifierPort`
(`format: "apple-appattest"`), pinned Apple root, RP-ID hash = SHA-256(App ID),
`nonce = SHA256(authData || clientDataHash)` check, `aaguid` = production, counter
monotonicity per key. The payload, nonce issuance and trace digest stay identical.
iOS client is Phase 2 (Apple Developer enrollment pending).
