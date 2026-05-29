-- V62: Opt-in email-domain enforcement flag for tenants.
--
-- Motivation:
--   tenant_email_domains (V44) already auto-binds a new registrant to the
--   tenant that owns their email domain. But registration NEVER rejects an
--   unknown domain — an unmatched user silently lands on the default tenant.
--   For organisations like Marmara University (which owns marmara.edu.tr for
--   staff/academics and marun.edu.tr for students) an admin may want a hard
--   gate: only addresses whose domain is in the tenant's registry may join.
--
--   This flag is OPT-IN. Default false preserves today's graceful behaviour
--   (auto-bind on match, fall through on miss). When set true, the
--   RegisterUserService rejects a registrant whose email domain is NOT in the
--   tenant's tenant_email_domains rows with EmailDomainNotAllowedException.
--
-- Idempotent — ADD COLUMN IF NOT EXISTS so replays are safe.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS enforce_domain_matching BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN tenants.enforce_domain_matching IS
    'Opt-in registration gate. When true, only registrants whose email domain '
    'is present in tenant_email_domains may join this tenant; others are '
    'rejected (EmailDomainNotAllowedException → HTTP 422). When false (default) '
    'registration is graceful: auto-bind on domain match, fall through to the '
    'default tenant on miss. See Flyway V44 (tenant_email_domains).';
