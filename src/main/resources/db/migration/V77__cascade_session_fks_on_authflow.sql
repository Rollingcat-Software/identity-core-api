-- V77: ON DELETE CASCADE for the TRANSIENT session FKs that reference auth_flows
-- / auth_flow_steps.
--
-- Editing an auth flow in the dashboard does create-replacement → delete-old →
-- update (AuthFlowsPage.handleSave), and deleting a flow is a normal admin
-- action. Both failed with 23503 once ANY login/verification session referenced
-- the flow (or its steps) — these FKs were NO ACTION:
--   mfa_sessions.flow_id              → auth_flows        (86 rows blocked the fivucsas edit)
--   auth_sessions.auth_flow_id        → auth_flows
--   verification_sessions.flow_id     → auth_flows
--   auth_session_steps.auth_flow_step_id → auth_flow_steps
-- They are all EPHEMERAL per-attempt session state (mfa_sessions are 10-min TTL;
-- the others are transient pipeline/login session rows). The durable audit trail
-- lives in audit_logs (NOT FK'd to auth_flows), so cascading these on flow/step
-- deletion loses no history — it just clears in-flight sessions, which re-login.
-- (auth_flow_steps→auth_flows and auth_flow_step_methods→auth_flow_steps already
-- CASCADE.) Idempotent: drop-if-exists then re-add with the cascade rule.

ALTER TABLE mfa_sessions DROP CONSTRAINT IF EXISTS mfa_sessions_flow_id_fkey;
ALTER TABLE mfa_sessions ADD CONSTRAINT mfa_sessions_flow_id_fkey
    FOREIGN KEY (flow_id) REFERENCES auth_flows(id) ON DELETE CASCADE;

ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_auth_flow_id_fkey;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_auth_flow_id_fkey
    FOREIGN KEY (auth_flow_id) REFERENCES auth_flows(id) ON DELETE CASCADE;

ALTER TABLE verification_sessions DROP CONSTRAINT IF EXISTS verification_sessions_flow_id_fkey;
ALTER TABLE verification_sessions ADD CONSTRAINT verification_sessions_flow_id_fkey
    FOREIGN KEY (flow_id) REFERENCES auth_flows(id) ON DELETE CASCADE;

ALTER TABLE auth_session_steps DROP CONSTRAINT IF EXISTS auth_session_steps_auth_flow_step_id_fkey;
ALTER TABLE auth_session_steps ADD CONSTRAINT auth_session_steps_auth_flow_step_id_fkey
    FOREIGN KEY (auth_flow_step_id) REFERENCES auth_flow_steps(id) ON DELETE CASCADE;
