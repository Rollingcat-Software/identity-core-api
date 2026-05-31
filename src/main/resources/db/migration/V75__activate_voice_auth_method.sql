-- V75: activate the VOICE login auth method (it was seeded INACTIVE by V16).
--
-- WHAT: VOICE is one of the platform's documented login auth methods (backed by
--   voice_enrollments + VoiceStep), but its auth_methods row has shipped with
--   is_active = FALSE since V16, so GET /api/v1/auth-methods filtered it out and
--   the dashboard auth-flow builder never offered it. Flip it to active.
--
-- WHY: tenants building auth flows should be able to place VOICE as a factor.
--   (GESTURE_LIVENESS is intentionally NOT added here — it is an active-liveness
--   anti-spoofing sub-component of FACE, NOT a standalone login/identity factor,
--   and has no auth handler; it must not appear as a selectable auth method.)
--
-- ADDITIVE / REVERSIBLE-SAFE: a single guarded UPDATE, idempotent, no schema or
--   constraint change. Applies cleanly from V74.
UPDATE auth_methods SET is_active = TRUE
 WHERE type = 'VOICE' AND is_active = FALSE;
