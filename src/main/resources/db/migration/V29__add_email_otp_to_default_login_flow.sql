-- V29: Add EMAIL_OTP as step 2 to the Default Login auth flow
-- This enables 2FA for users who have enabled it in their settings.
-- Step 1 (PASSWORD) is handled by the login endpoint itself.
-- Step 2 (EMAIL_OTP) is the secondary verification step shown by the frontend.

INSERT INTO auth_flow_steps (auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts)
SELECT
    'e986943a-3646-4820-8943-8260ed55cbb8', -- Default Login flow
    '605de186-6887-455b-b6d1-035e9f26b406', -- Email OTP method
    2,
    true,
    300,
    3
WHERE NOT EXISTS (
    SELECT 1 FROM auth_flow_steps
    WHERE auth_flow_id = 'e986943a-3646-4820-8943-8260ed55cbb8'
      AND step_order = 2
);
