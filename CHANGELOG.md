# Changelog - Identity Core API

## [2026-04-16] — PR-1 Hosted-first V1 + PR-1 review blockers

### Added
- **OAuth2 hosted-login** — `OAuth2Controller.authorize` `display=page` branch → 302 to `verify.fivucsas.com/login`; `POST /oauth2/authorize/complete` mints authorization code after MFA; `GET /oauth2/clients/{clientId}/public` returns branding metadata (OAuth2Controller.java +209 lines)
- **B1 permitAll** — `/oauth2/authorize/complete` + `/oauth2/clients/*/public` added to SecurityConfig permitAll chain; new `OAuth2PublicEndpointsSecurityIntegrationTest` hits the real SecurityFilterChain (NOT `addFilters=false`) to catch the anonymous-auth regression unit tests missed (SecurityConfig.java)
- **V34** Flyway migration — `oauth2_clients.confidential` boolean column for public-vs-confidential client distinction
- **V35** Flyway migration — `mfa_sessions.consumed_at` TIMESTAMP + `MfaSession.consume()` method for atomic code-mint replay guard (B4)
- **V36** Flyway migration — `mfa_sessions.client_id` column; enforced at `/authorize/complete` to block cross-client code replay within the same tenant (B2)
- **RFC 8252 loopback** — `OAuth2Client.matchesLoopbackRegistration()`: IPv4 `127.0.0.1` only (no `localhost`, no IPv6 `::1`), rejects any incoming query string, fragment tolerated (B5)
- **PKCE S256 enforcement** — `/authorize/complete` mandates `codeChallenge` + `codeChallengeMethod=S256` when `OAuth2Client.confidential == false`; rejects `plain` (B3)
- **Jackson redirect URI parsing** — `OAuth2Client.splitRegisteredRedirectUris()` uses `ObjectMapper.readValue(json, new TypeReference<List<String>>(){})` with malformed-JSON single-URI fallback; URIs with commas no longer corrupt allowlist (B6)
- **OAuth2ControllerTest** — 199 LOC covering new endpoints
- **OAuth2ClientTest** — 169 LOC covering exact-match + loopback-match including anyIncomingQueryIsRejected, fragmentIsTolerated, ipv6LoopbackRejected, variousPortsAccepted (13 tests)

### Fixed
- **Atomic code-mint** — `/authorize/complete` wraps code-mint + session-consume in `@Transactional`; `consumed_at` set BEFORE mint so retries fail fast (B4)
- **Tenant-mismatch status code** — `/oauth2/authorize/complete` returns 400 `invalid_request` instead of 403 per RFC 6749 §5.2 (no policy leak to unauthenticated callers)
- **Rate-limit `Retry-After`** — `/authorize/complete` and `/auth/login` 429 responses include `Retry-After` header so well-behaved clients back off (RateLimitInterceptor.java)
- **completedMethods derivation** — `AuthenticateUserService` derives from `MfaSession.getCompletedMethods()` instead of hardcoded `[PASSWORD]`; supports tenants whose first step isn't password
- **Cross-client replay** — MFA session bound to originating `client_id` at creation; `/authorize/complete` rejects session if `clientId` mismatches (B2)

### Changed
- **OAuth2Controller.authorize** — dropped redundant `isHtmlAccept` branch now that SDK always sets `display=page` explicitly

### Commits (preserved via merge-commit strategy on PR #16)
- `86ed1bf` permitAll hosted-login OAuth2 endpoints (B1)
- `ad293ce` Jackson redirect_uris parser (B6)
- `76d3b8c` PKCE S256 mandated for public clients (B3)
- `d840b8e` atomic MFA session consumption V35 (B4)
- `1f7993b` / `ae1bb7f` loopback hardening (B5 + IPv4/query tightening)
- `9d97e40` client_id bound to MfaSession V36 (B2)
- `5c9ed62` 403 → 400 on tenant mismatch
- `5daff87` drop isHtmlAccept branch
- `db5da7f` Retry-After on 429
- `aea7a9a` derive completedMethods from MfaSession
- Merged to main in `8059ca9` (fast-forward)

## [2026-04-15]

### Added
- **Rate limit** on `/auth/mfa/qr-generate` — defends against broken clients looping on QR generation. Uses biometric bucket (20/min per IP). Sends `Retry-After` header so the widget can surface a friendly countdown instead of re-firing. (RateLimitInterceptor.java)

## [Unreleased] - 2026-03-07

### Added
- CLAUDE.md with project context, known issues, and auth handler status
- ROADMAP.md with phased integration plan
- AUTH method integration gap analysis in TODO.md (8 new items: AUTH-1 through AUTH-8)

### Documented
- Auth handler status matrix: 7/10 methods working, 3 broken at runtime
- NfcDocumentAuthHandler always returns failure (hardcoded stub)
- FingerprintAuthHandler/VoiceAuthHandler fail due to biometric-processor stubs
- WebAuthnController registration endpoints ready but no frontend enrollment UI
- TotpController/QrCodeController not connected to frontend components
- BiometricServicePort cross-service integration gaps

### Previous
- Cross-module integration audit (March 2026): 41 issues identified
- Previous audit (Feb 2026): 74/100 readiness score, 3 critical issues

## [2026-04-15b] — MFA reuse check fix

### Fixed
- **TOTP + EMAIL_OTP collision**: reuse check compared AMR values, but both TOTP and EMAIL_OTP map to RFC 8176 `"otp"`. After TOTP completed, subsequent EMAIL_OTP returned 400 "METHOD_ALREADY_USED". Now reuse is tracked by `AuthMethodType.name()` (e.g. "TOTP", "EMAIL_OTP") and AMR values are mapped at JWT issuance. (AuthController.java, AuthenticateUserService.java)
