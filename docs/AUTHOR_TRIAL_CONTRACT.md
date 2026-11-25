# Author-trial contract (Paper B, BPCER/APCER measurement)

Status: implementation contract for the authors-only trial mode (owner decision
2026-11-24). The three product repositories and the analysis repository implement
this document; any change to a wire name or a CSV column must change this file in
the same PR.

## 1. Purpose and scope

The authors (P1-P4 pseudonymous codes; the name mapping is kept offline) run
genuine login attempts on their own pre-enrolled accounts in one dedicated test
tenant, and attack attempts as another consenting author's account with a live
face-swap / deepfake / virtual-camera instrument. Each attempt runs the REAL
Puzzle + face-identity verification path. The server records the decision; the
export is the input of the ISO/IEC 30107-3 analysis (BPCER, APCER, full-system
rates). No image, video, audio or biometric template is stored in the attempt
log. The trial data and the bound templates are deletable with one documented
command.

## 2. Participants and accounts

`author_trial_participants` maps a pseudonymous code to one pre-created account
in the trial tenant:

| column | meaning |
|---|---|
| `tenant_id` | the dedicated trial tenant |
| `participant_code` | `P1`..`P4` (no name, never an email in any log/export) |
| `user_id` | the bound account; its face template is the genuine reference |
| `enrolled_at` | set by the trial enroll endpoint after face + PUZZLE enrollment |

No row exists for a person who is not an author. The page lists only these codes.
The name mapping lives offline and is never written by this feature.

## 3. Identity-core-api surface

Base path `/api/v1/author-trial`. Every endpoint requires the header
`X-Author-Trial-Key: <access-code>` (constant-time compare). The whole surface
answers 404 when `app.author-trial.enabled=false` or the tenant is not in
`app.author-trial.tenant-ids`; a wrong key answers 401. The endpoints are
`permitAll` in Spring Security because the key is the gate (there is no user
login on the page).

### 3.1 `GET /participants`

```json
{
  "tenantId": "<uuid>",
  "participants": [{"code": "P1", "enrolled": true}, {"code": "P2", "enrolled": false}],
  "flow": {
    "method": "PUZZLE",
    "binding": true,
    "difficulty": "easy",
    "count": 1,
    "challenges": ["blink", "smile", "..."]
  }
}
```

`challenges` is the tenant flow's PUZZLE allow-list (bio action names), in the
order stored in the flow. No email, no user id, no name.

### 3.2 `POST /session`

Request:

```json
{
  "participantCode": "P1",
  "mode": "genuine" | "attack",
  "targetCode": "P2",
  "instrument": "DeepFaceLive 2.0",
  "instrumentPreset": "deepfacelive",
  "device": {"label": "...", "os": "...", "browser": "...", "screen": "1920x1080@2",
             "cameraLabel": "...", "cameraResolution": "1280x720",
             "hardwareConcurrency": 8, "deviceMemoryGB": 8, "type": "computer"},
  "env": {"localTimeOfDay": "21:14", "brightness": 0.42,
          "exposureScore": 0.03, "frameRate": 29.8},
  "webVersion": "<build id>"
}
```

- `mode=genuine` requires `participantCode` (target = participant).
- `mode=attack` requires `targetCode` different from `participantCode`; both
  must be configured participants of the trial tenant.
- `instrument` is free text, max 120 chars; `instrumentPreset` is one of
  `live_face_swap`, `deepfake_replay`, `virtual_camera`, `other` (or absent).
- `device`/`env` are sanitised (allow-listed scalar keys, control characters
  stripped, values bounded) and stored as JSON; they are never used for an auth
  decision.

Response 200:

```json
{
  "attemptId": "<uuid>",
  "mfaSessionToken": "<opaque MFA session token>",
  "participantCode": "P1",
  "targetCode": "P2",
  "mode": "attack",
  "round": 1,
  "position": 3,
  "challenge": "blink",
  "binding": true,
  "difficulty": "easy",
  "count": 1,
  "puzzleConfig": {
    "allowedChallengeTypes": ["blink"],
    "count": 1,
    "difficulty": "easy",
    "alsoMatchFaceIdentity": true
  }
}
```

The server:
1. Resolves the target account and resets its login strike counter/lock (a
   trial attempt must never be refused by the 5-strike lock; the reset is logged).
2. Assigns the next slot of the server-side round plan for
   `(tenant, participant, mode)`: a round is a random permutation of the flow's
   PUZZLE challenge list; `position` is 1..N. When a round is exhausted a new
   permutation starts at round+1.
3. Creates a REAL MFA session for the target account through the
   identifier-first path (`beginIdentifierLogin`) — no password is involved. The
   trial tenant must have config-driven login on and a default APP_LOGIN flow
   whose step 1 is PUZZLE; otherwise the endpoint answers 409
   `TRIAL_FLOW_NOT_CONFIGURED`.
4. Inserts a pending `author_trial_attempts` row carrying the plan slot, the
   target/operator codes, mode/instrument, binding flag from the flow, and the
   device/env snapshot.

The page then drives the existing real Puzzle step with `mfaSessionToken`.

### 3.3 Puzzle session proxy override

`POST /api/v1/auth/mfa/puzzle/session` (existing, unchanged for every other
tenant) detects a trial attempt by the MFA session id and, ONLY for that
attempt, overrides the bio session policy:

- `allowed_challenge_types = [attempt.challenge]`
- `count = 1`
- `difficulty = "easy"` (bio contract v2 enforces >= 2 challenges at
  `standard`; one challenge per attempt is what makes a round cover every
  puzzle exactly once)
- `alsoMatchFaceIdentity` = the flow step's value (recorded on the attempt as
  `binding`)

It records the issued `session_id`, the `trace_contract` advertised by bio, and
the issued action. A second CREATE for the same attempt answers 409
`TRIAL_SESSION_ALREADY_CREATED` (one bio session per attempt, so the
per-challenge failure cap cannot be reset).

`POST .../{sessionId}/challenge` records the per-challenge verdict
(`last_challenge_verdict`, `last_challenge_reason`, `challenges_submitted += 1`)
for a trial session and forwards the response unchanged.

### 3.4 Decision recording (server-side, authoritative)

`PuzzleVerifyMfaStepHandler` records, for a trial MFA session:

- `liveness_verdict = fail` when bio's verdict is not verified;
- when liveness passed and binding is off: `liveness_verdict=pass`,
  `identity_verdict=na`, `step_outcome=pass`;
- when binding is on: `liveness_verdict=pass` then `identity_verdict=pass|fail`
  (the embedding match result), with `identity_score`, `identity_distance`,
  `identity_threshold` from bio's `/verify-embedding` response when present;
- `step_outcome=fail` plus a reason on any fail-closed path (missing session id,
  missing/malformed embedding, missing binding frame, identity mismatch).

On final MFA completion (`VerifyMfaStepService.completeMfa`) the attempt becomes
`outcome=accept` with `decided_at`/`latency_ms` (the accept decision comes from
the real login machinery, never from the page). A failed step records
`outcome=reject` (a later successful retry may overwrite it; the page does not
retry within an attempt).

The recorder is best-effort: a recording failure is logged and NEVER changes or
blocks an authentication decision.

### 3.5 `POST /attempts/{attemptId}/finish`

Request:

```json
{
  "clientOutcome": "accepted" | "rejected" | "error" | "abandoned",
  "clientLatencyMs": 12345,
  "failureReason": "camera_timeout",
  "device": {"...": "..."},
  "env": {"...": "..."}
}
```

The server keeps an authoritative `accept` (already recorded) and an
authoritative verdict (`liveness_verdict=fail` or `identity_verdict=fail` ->
`reject`). Otherwise `error`/`abandoned` are stored as such; a client
`accepted` without a server completion is stored as `reject` (fail closed).
This endpoint exists for technical failures (camera error, Stop mid-attempt,
page timeout) and for last-chance device/env metadata; it can never turn a
failed or pending attempt into an accept.

### 3.6 `POST /enroll`

Request: `{"participantCode":"P1","embedding":[512 floats],"webVersion":"..."}`.

Calls the real biometric `/enroll-embedding` path for the bound account, then
completes the FACE and PUZZLE enrollments (the same bookkeeping the normal
enrollment flow performs) and sets `author_trial_participants.enrolled_at`.
Idempotent (re-enroll replaces/updates the template). If identity's
face-embedding liveness mode is ENFORCE the bio call may answer
`FACE_IMAGE_REQUIRED`; that surfaces as 409 with code
`TRIAL_ENROLL_IMAGE_REQUIRED` (the runbook keeps the trial tenant in AUDIT/OFF
for enrollment).

### 3.7 `GET /export?format=csv|json`

CSV with `Content-Type: text/csv; charset=utf-8`,
`Content-Disposition: attachment; filename="author_trial_sessions.csv"`,
`Cache-Control: no-store`. Rows are attempts with `outcome` accept/reject;
pending/error/abandoned rows are included with `excluded=yes` so the analysis
can count and skip them. JSON returns the same rows as objects.

The CSV header is the OLD `sessions.csv` schema, in its original order, followed
by the documented extension columns:

```
date,participant,operator,session_no,condition,attack_type,attack_medium,binding,k,
difficulty,contract,face_embedding_liveness_mode,deployment_commits,outcome,
liveness_verdict,identity_verdict,failure_reason,completion_time_s,device_browser,
lighting,server_session_id,excluded,notes,
mode,target,instrument,instrument_preset,round,position,challenge,planned_challenge,
identity_score,identity_distance,identity_threshold,latency_ms,client_latency_ms,
started_at,decided_at,local_time_of_day,brightness,exposure_score,frame_rate,
camera_label,camera_resolution,device_label,os,browser,screen,web_version,
api_version,bio_version,mfa_session_id,step_outcome,challenges_submitted,
last_challenge_verdict,last_challenge_reason,attempt_id
```

Mapping notes:

| column | value |
|---|---|
| `date` | UTC date of `started_at` |
| `participant` | target/victim code (the account whose template was checked) |
| `operator` | the author who performed the attempt |
| `session_no` | 1-based per `participant`, ordered by `started_at` |
| `condition` | `bona_fide` (genuine) or `attack` |
| `attack_type` | `none`; or `live_face_swap`, `deepfake_replay`, `virtual_camera`, `other` from `instrument_preset` (free text maps to `other`) |
| `attack_medium` | `instrument` (attack) / empty |
| `binding` | `on`/`off` |
| `k` | challenges issued in the bio session (1) |
| `difficulty` | `easy` (the trial policy) |
| `contract` | `v2`/`v1` from the CREATE advertisement |
| `face_embedding_liveness_mode` | `off`/`audit`/`enforce` at attempt time |
| `deployment_commits` | `bio=<version>;api=<version>;web=<webVersion>` |
| `outcome` | `accept`/`reject`; error/abandoned only when excluded |
| `liveness_verdict` | `pass`/`fail`/empty |
| `identity_verdict` | `pass`/`fail`/`na`/empty |
| `failure_reason` | server or client reason |
| `completion_time_s` | (decided_at - started_at) in seconds |
| `device_browser` | `<device_label> / <os> / <browser> / <camera_label>` |
| `lighting` | `bright` >= 0.65, `moderate` >= 0.4, `dim` >= 0.2, `dark` below, `unknown` |
| `server_session_id` | bio puzzle session id |
| `excluded` | `yes` for pending/error/abandoned, empty otherwise |
| `notes` | instrument preset + error text, CSV-escaped |
| `mode` | `genuine`/`attack` |
| `target` | target code (= participant for genuine) |
| `round`, `position`, `challenge` | plan slot and issued action |
| `planned_challenge` | the plan action (may differ from `challenge` only on a server anomaly; both are exported) |
| `identity_score` | bio `/verify-embedding` `confidence` |
| `latency_ms` | server-measured attempt latency |
| `client_latency_ms` | page-measured attempt latency |
| `local_time_of_day` | client local `HH:MM` |
| `brightness` | 0..1 mean luma |
| `exposure_score` | 0..1 clipped-pixel fraction |
| `frame_rate` | measured fps |
| `camera_label` | MediaDeviceInfo label (no id) |
| `camera_resolution` | `WxH` |
| `device_label`, `os`, `browser`, `screen` | sanitised device snapshot |
| `web_version`, `api_version`, `bio_version` | version pins |
| `mfa_session_id` | identity MFA session id |
| `step_outcome` | `pass`/`fail`/empty |
| `challenges_submitted` | count |
| `last_challenge_verdict`, `last_challenge_reason` | last per-challenge SUBMIT |
| `attempt_id` | stable attempt uuid |

### 3.8 Data deletion

One documented command: `psql -v tenant_id='<trial-tenant-uuid>' -f
scripts/author-trial-purge.sql` (run by the coordinator on mordecai). The script
soft-deletes the bound users, enqueues the biometric-deletion outbox rows
(FACE/VOICE) so the worker removes the templates, and deletes
`author_trial_attempts`, `author_trial_plan_entries` and
`author_trial_participants` for the tenant, in one transaction. It never hard
deletes users (V53 trigger) and is idempotent.

## 4. Configuration

identity-core-api (`application.yml` + `docker-compose.prod.yml` environment):

| env | default | meaning |
|---|---|---|
| `AUTHOR_TRIAL_ENABLED` | `false` | whole surface off -> 404 |
| `AUTHOR_TRIAL_ACCESS_CODE` | empty | shared key; empty -> surface off |
| `AUTHOR_TRIAL_TENANT_IDS` | empty | comma-separated trial tenant allow-list |

The trial tenant also needs, as in the pilot environment plan:
`APP_AUTH_CONFIG_DRIVEN_LOGIN_TENANTS=<trial>`, `APP_AUTH_PUZZLE_LAYER_TENANTS=<trial>`,
`APP_AUTH_CLIENT_SIDE_EMBEDDING` (+ tenants) on. biometric-processor:
`PUZZLE_TRACE_V2_ENABLED=true`. web-app build: `VITE_CLIENT_SIDE_EMBEDDING=true`.
Attested binding stays off (no browser can attest).

The trial flow: one APP_LOGIN default flow, step 1 = PUZZLE only, allow-list =
the web-renderable bio action names, `alsoMatchFaceIdentity=true`. The trial
overrides count=1/easy per session as above.

## 5. Web page

Route `/author-trial`, public (no dashboard login), same shell style as
`/devbench`. One screen: access-code gate, "Ben kimim" participant dropdown
(only configured codes; enroll button when `enrolled=false`), device dropdown
pre-filled from auto-detection and editable, attack-mode toggle with a target
dropdown and instrument preset/free text, Start/Stop, round/position/challenge
progress, live stats and a feed. Start runs a continuous loop of attempts until
Stop. Each attempt: probe the camera for brightness/exposure/fps -> create the
trial session -> render the SHARED `PuzzleStep` through `MfaStepRenderer` with
the returned MFA session token and `puzzleConfig` -> await the real
`POST /auth/mfa/step` -> finish the attempt -> next (short pause). A per-attempt
timeout (default 120 s, overridable for tests) finishes the attempt as
`error`/`abandoned`; Stop finishes an in-flight attempt as `abandoned`.
Enrollment uses the existing `FaceEnrollmentFlow` capture, computes the
Facenet512 embedding with `embedCapturedFace`, and posts it to `/enroll`. No raw
frame is stored or sent to the attempt log.

## 6. Analysis (fivucsas-papers)

`bench/pilot/analyze.py` detects the trial schema (presence of `attempt_id` and
`mode`) and prints:

- BPCER per subject, per challenge, per condition and pooled: genuine attempts
  whose PAD/liveness verdict is `fail`; full-system genuine rejection (step
  outcome reject) is reported separately and never called BPCER;
- APCER per subject, per instrument and pooled: attack attempts whose liveness
  verdict passed; full-system attack success (step accept) reported separately;
- Wilson score and exact Clopper-Pearson 95% intervals for every count, and a
  subject-level bootstrap interval for the pooled rates (subjects resampled with
  replacement; the number of distinct resamples and the within-subject
  correlation caveat are printed);
- excluded rows counted and skipped; every rate names its configuration
  (binding, k, difficulty, liveness mode).

The existing non-trial path and its tests stay unchanged.