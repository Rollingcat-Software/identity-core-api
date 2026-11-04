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
earlier in the same MFA session** (`session.getCompletedMethods()` contains
`PUZZLE`). A PUZZLE completed *after* FACE does not count. That is a deliberate
trade-off, and no production flow has that order today.

`FaceEmbeddingLivenessPolicy` decides what happens to an unpaired embedding. It
decides before any matching, so the response never reveals whether the face would
have matched.

| Mode | Paired | Login (`FaceVerifyMfaStepHandler`) |
|---|---|---|
| OFF | any | Same as before the rule, no extra logging |
| AUDIT (default) | yes | Unchanged |
| AUDIT | no | Unchanged, plus a WARN log and the audit event `FACE_EMBEDDING_UNPAIRED` |
| ENFORCE | yes | Unchanged (embedding path) |
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

Audit rows go through `AuditLogPort.logSecurityEvent`. They carry the user, tenant,
step and user agent, and never the embedding. If the audit write fails, the outcome
does not change.

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

**Rollback:** set the mode to `AUDIT` (or `OFF`) and restart identity. Nothing is persisted.

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
- Templates already enrolled from embeddings stay unverified.
- MiniFASNet can false-reject on poor webcams.
- Under ENFORCE without PUZZLE, the server sees the face image again, so the "on-device"
  privacy property does not hold for those flows.
- The image path adds CPU load on bio.
