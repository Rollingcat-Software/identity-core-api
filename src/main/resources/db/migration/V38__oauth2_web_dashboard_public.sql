-- V38: Flip fivucsas-web-dashboard SPA client to public (confidential=false) per 2026-04-18 plan — browser-context public client, PKCE S256 already enforced end-to-end.

UPDATE oauth2_clients SET confidential = false, updated_at = NOW() WHERE client_id = 'fivucsas-web-dashboard';
