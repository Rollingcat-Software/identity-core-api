# Changelog - Identity Core API

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
