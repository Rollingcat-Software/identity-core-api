# Face embedding liveness rule (gap Ü2)

## Problem

With `app.auth.client-side-embedding` on, the browser computes the Facenet512
embedding and sends only the 512 floats. The biometric processor can match an
embedding, but it cannot run presentation-attack detection (PAD) on it, because
there is no frame. Before this rule, an embedding FACE factor was accepted with no
liveness evidence at all. The comments said it "MUST be paired" with a liveness
factor, but nothing enforced that.

## Rule

The only liveness evidence accepted for an embedding is a **PUZZLE completed
earlier in the same MFA session whose identity binding ran and passed, on exactly
this embedding**:

1. `session.getCompletedMethods()` contains `PUZZLE`, and
2. that PUZZLE ran its identity binding (`puzzleConfig.alsoMatchFaceIdentity` on and
   the client-side-embedding policy on) and the match passed. Only then does
   `PuzzleVerifyMfaStepHandler` store the SHA-256 of the embedding it matched on the
   MFA session (`mfa_sessions.liveness_embedding_sha256`, migration V88; the
   embedding itself is never stored), and
3. the FACE step sends the same vector: its digest (`LivenessEmbeddingDigest`, over the
   IEEE-754 bits of every value, constant-time compare) equals the stored one.

Why all three: a PUZZLE without binding proves only that *some* live person solved it,
not whose face it was. Without the digest, an attacker who holds the earlier factors
could solve the PUZZLE with their own live face and then send the victim's embedding
(computed from a photo, with a modified client) on the FACE step. Each failed condition
gives a reason that goes into the audit row: `NO_PUZZLE`, `PUZZLE_NOT_BOUND`,
`EMBEDDING_MISMATCH`. All three count as unpaired.

A PUZZLE completed *after* FACE does not count. That is a deliberate trade-off, and no
production flow has that order today.

**Client impact:** today's web-app computes a fresh embedding for the FACE step, so it
does not send the PUZZLE's vector again. Under ENFORCE a PUZZLE-then-FACE login is
therefore unpaired (`EMBEDDING_MISMATCH`) and takes the image path through the
`FACE_IMAGE_REQUIRED` re-send. It still works, but the frame reaches the server. Keeping
the image on the device in that flow needs the client to reuse the PUZZLE's embedding
for the FACE step.

`FaceEmbeddingLivenessPolicy` decides what happens to an unpaired embedding. It
decides before any matching, so the response never reveals whether the face would
have matched.

| Mode | Paired | Login (`FaceVerifyMfaStepHandler`) |
|---|---|---|
| OFF | any | Same as before the rule, no extra logging |
| AUDIT (default) | yes | Unchanged, plus the audit event `FACE_EMBEDDING_PAIRED` |
| AUDIT | no | Unchanged, plus a WARN log and the audit event `FACE_EMBEDDING_UNPAIRED` |
| ENFORCE | yes | Unchanged (embedding path), audit event `FACE_EMBEDDING_PAIRED` |
| ENFORCE | no, `image` in the payload | Image path (bio passive PAD), audit event `FACE_EMBEDDING_REROUTED_TO_IMAGE` |
| ENFORCE | no, no image | Non-terminal challenge (see below), audit event `FACE_IMAGE_REQUIRED` |

Challenge body (HTTP 200, returned through the orchestrator's existing passthrough):

```json
{"status":"FACE_IMAGE_REQUIRED","method":"FACE","requiredInput":"image",
 "currentStep":2,"totalSteps":2,"message":"Face verification requires an image capture"}
```

What the challenge does and does not touch:

- It records no failed-attempt strike.
- It adds no completed method, so the image re-send does not trip `METHOD_ALREADY_USED` and `amr` is unchanged.
- It does not advance the step and does not slide the session TTL.
- The per-IP and endpoint rate limits still apply.

These parts are unchanged:

- The image-path verdict rule: `SPOOF_DETECTED` hard-fails, and only bio's `verified` field is trusted.
- A malformed embedding still falls through to the image path.
- `completeMfa`.

**Enrollment** (`EnrollBiometricService`, behind
`POST /api/v1/biometric/enroll-embedding/{userId}`):

- **AUDIT:** the enrollment is accepted and audited as `FACE_EMBEDDING_ENROLL_UNPAIRED`.
- **ENFORCE:** a self-service embedding enrollment gets 409, with
  `code`, `error` and `errorCode` all set to `FACE_IMAGE_REQUIRED`. The client then enrolls
  with an image through the multipart `/enroll`. An operator with `biometric:enroll`
  enrolling another user is still allowed, and the enrollment is audited as
  `FACE_EMBEDDING_ENROLL_ON_BEHALF`.
- **Which tenant decides the mode:** the authenticated principal's tenant, never the
  `tenant_id` in the request body. The body value is only the bio scoping hint and is
  client-controlled, so a self-service user of a canary-ENFORCE tenant could otherwise
  name another tenant (or a non-UUID string) and fall back to the global AUDIT. The
  controller passes the principal's tenant as `EnrollBiometricCommand.livenessTenantId`.
  Login already uses the server-side `MfaSession.tenantId`.

Audit rows go through `AuditLogPort.logSecurityEvent`. They carry the user, tenant,
step, user agent and (login) the pairing reason, and never the embedding. If the audit
write fails, the outcome does not change.

## Configuration

| Property | Env | Default |
|---|---|---|
| `app.auth.face-embedding-liveness.mode` | `APP_AUTH_FACE_EMBEDDING_LIVENESS_MODE` | `AUDIT` |
| `app.auth.face-embedding-liveness.enforce-tenants` | `APP_AUTH_FACE_EMBEDDING_LIVENESS_ENFORCE_TENANTS` | empty |

- **Canary list:** comma-separated tenant UUIDs, parsed the same way as `ClientSideEmbeddingPolicy`.
  A listed tenant gets ENFORCE while the global mode is AUDIT. OFF is the full kill-switch
  and ignores the list. Invalid UUIDs are skipped with a warning.
- **Unknown mode values** parse to AUDIT. A typo cannot cause a lockout.
- **Compose:** the variable is forwarded in the `docker-compose.prod.yml` `environment:` block.

**Rollback:** set the mode to `AUDIT` (or `OFF`) and restart identity. The only
persisted state is the nullable `mfa_sessions.liveness_embedding_sha256` column (V88),
which lives only as long as the MFA session and needs no rollback.

## Rollout

1. **R1:** this change with AUDIT. Production behaviour is identical. Count the
   `FACE_EMBEDDING_UNPAIRED` and `FACE_EMBEDDING_ENROLL_UNPAIRED` rows.
2. **R2:** the web-app handles the status. It re-sends the captured frame once on
   `FACE_IMAGE_REQUIRED`, shows an error on a second one, and on a 409 from enroll-embedding
   falls back to image enrollment.
3. **R3:** pre-flight checks. None of these were checked when this change was written:
   - Does production bio accept image `/verify`?
   - Is `PuzzleLayerPolicy` on?
   - Is bio `ENROLL_LIVENESS_ENABLED` on?
   - Do the mobile clients send embeddings, and do they handle the new status?
4. **R4:** ENFORCE for one test tenant through the canary list, then the real tenants, then
   global. Any tenant served by a mobile client stays in AUDIT until that client handles
   `FACE_IMAGE_REQUIRED`.

Before ENFORCE goes on for a tenant, drive a real browser on the canary tenant through
three journeys: FACE as a choice option, password + face, and PUZZLE then FACE. Check
the PAD verdict in the bio logs, and record the image-path p95 on the CPU-only bio.

## Residual risks

- Passive PAD gives only medium assurance.
- The PUZZLE v2 binding frame is not tied to the live capture, except with Android attestation.
  The digest ties the FACE step to the vector the PUZZLE matched, but without attestation a
  modified client can still choose which vector it sends on the PUZZLE step itself.
- Templates already enrolled from embeddings stay unverified.
- MiniFASNet can false-reject on poor webcams.
- Under ENFORCE without PUZZLE, the server sees the face image again, so the "on-device"
  privacy property does not hold for those flows.
- The image path adds CPU load on bio.
