package com.fivucsas.identity.exception;

import com.fivucsas.identity.domain.exception.*;
import com.fivucsas.identity.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound(
            UserNotFoundException ex,
            HttpServletRequest request) {
        log.warn("User not found: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.NOT_FOUND.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * P0-#5 (INVESTIGATION_MASTER_2026-05-07): surface a dedicated 423 Locked
     * response when the user account is locked, carrying the remaining-seconds
     * value so the frontend can render its localized
     * {@code errors.ACCOUNT_LOCKED} message with a {{minutes}} interpolation.
     *
     * <p>Response shape (extends the standard ErrorResponse envelope with one
     * extra field):
     * <pre>
     * {
     *   "timestamp": "...",
     *   "status": 423,
     *   "error": "ACCOUNT_LOCKED",
     *   "errorCode": "ACCOUNT_LOCKED",
     *   "message": "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
     *   "remainingLockTimeSeconds": 873,
     *   "path": "/api/v1/auth/login"
     * }
     * </pre>
     */
    /**
     * SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted — NIST 800-63B
     * §5.1.1.2 5-strike counter trip. The primitive ({@code OtpService.validateWithResult})
     * surfaces an {@code exhausted=true} terminal state when the user has
     * burned through {@code MAX_ATTEMPTS} mismatches on a single issued code.
     * Previously the 5 MFA OTP call-sites used the boolean {@code validate()}
     * overload and threw the flag away — users waited 5min for TTL instead of
     * getting "send another OTP".
     *
     * <p>Maps to HTTP 429 with a {@code Retry-After} hint and the existing
     * {@code OTP_ATTEMPTS_EXHAUSTED} error code so the frontend can short-
     * circuit to "request a new code" instead of looping on the verify form.
     */
    @ExceptionHandler(OtpAttemptsExhaustedException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleOtpExhausted(
            OtpAttemptsExhaustedException ex,
            HttpServletRequest request) {
        log.warn("OTP attempts exhausted: path={}, ip={}",
                request.getRequestURI(), request.getRemoteAddr());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("action", "resend");
        body.put("remainingAttempts", 0);
        body.put("path", request.getRequestURI());

        // RFC 6585 §4: 429 responses SHOULD carry Retry-After. OTP TTL is 5
        // minutes so a fresh /send must wait at most that long; clients can
        // use this as a hint for when re-sending becomes useful.
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "300")
                .body(body);
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleAccountLocked(
            AccountLockedException ex,
            HttpServletRequest request) {
        log.warn("Account locked: path={}, remainingSeconds={}",
                request.getRequestURI(), ex.getRemainingLockTimeSeconds());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.LOCKED.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("remainingLockTimeSeconds", ex.getRemainingLockTimeSeconds());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.LOCKED).body(body);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(
            InvalidCredentialsException ex,
            HttpServletRequest request) {
        log.warn("Invalid credentials attempt from: {}", request.getRemoteAddr());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    /**
     * T-TENANT-GATE (2026-05-07): tenant-mismatch surface. Mapped to HTTP 403
     * Forbidden — semantically distinct from 401 (which the frontend treats as
     * "wrong password") and from 423 (account locked).
     *
     * <p>Response body extends the standard envelope with a
     * {@code requiredTenant} field so the frontend can interpolate the tenant
     * display name into a localized message
     * ("This account is not a {{tenant}} member."). Does not leak whether the
     * email exists — the 403 is fired only after the email is found, but the
     * tenant identity on the hosted login surface is already public knowledge
     * (the user is literally on that tenant's branded login page).</p>
     *
     * <pre>
     * {
     *   "timestamp": "...",
     *   "status": 403,
     *   "error": "TENANT_MISMATCH",
     *   "errorCode": "TENANT_MISMATCH",
     *   "message": "Account does not belong to the requested tenant",
     *   "requiredTenant": "Marmara University",
     *   "path": "/api/v1/auth/login"
     * }
     * </pre>
     */
    @ExceptionHandler(TenantMismatchException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleTenantMismatch(
            TenantMismatchException ex,
            HttpServletRequest request) {
        log.warn("Tenant mismatch on login: requiredTenant={}, path={}",
                ex.getRequiredTenant(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.FORBIDDEN.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("requiredTenant", ex.getRequiredTenant());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateEmail(
            DuplicateEmailException ex,
            HttpServletRequest request) {
        log.warn("Duplicate email: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * P0-#7 (INVESTIGATION_MASTER_2026-05-07): tenant user-quota exceeded.
     * Mapped to HTTP 409 Conflict — same status family as
     * {@link DuplicateEmailException} (the request cannot be fulfilled given
     * the current resource state). The body carries {@code maxUsers} so the
     * admin UI can render "Tenant capped at N users" without a second API
     * round-trip.
     *
     * <pre>
     * {
     *   "timestamp": "...",
     *   "status": 409,
     *   "error": "TENANT_USER_QUOTA_EXCEEDED",
     *   "errorCode": "TENANT_USER_QUOTA_EXCEEDED",
     *   "message": "Tenant has reached its maximum user quota (100)",
     *   "maxUsers": 100,
     *   "path": "/api/v1/auth/register"
     * }
     * </pre>
     */
    @ExceptionHandler(TenantUserQuotaExceededException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleTenantUserQuotaExceeded(
            TenantUserQuotaExceededException ex,
            HttpServletRequest request) {
        log.warn("Tenant user quota exceeded: maxUsers={}, path={}",
                ex.getMaxUsers(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.CONFLICT.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("maxUsers", ex.getMaxUsers());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    /**
     * V62: opt-in email-domain enforcement rejected this registration. Mapped to
     * HTTP 422 Unprocessable Entity — the caller is permitted to hit the
     * registration endpoint, but the submitted email-domain is semantically
     * unacceptable for the target tenant (a request-content problem). The body
     * carries {@code emailDomain} so the UI can surface a precise message.
     */
    @ExceptionHandler(EmailDomainNotAllowedException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleEmailDomainNotAllowed(
            EmailDomainNotAllowedException ex,
            HttpServletRequest request) {
        log.warn("Registration refused — email domain not allowed: {}, path={}",
                ex.getEmailDomain(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.UNPROCESSABLE_ENTITY.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("emailDomain", ex.getEmailDomain());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(body);
    }

    /**
     * Phase-2 account-link request rejected by a business rule (target inactive,
     * same-tenant link, unlink target outside the caller's identity, etc.).
     * HTTP 422 Unprocessable Entity — the request was well-formed but cannot be
     * satisfied.
     */
    @ExceptionHandler(IdentityLinkException.class)
    public ResponseEntity<ErrorResponse> handleIdentityLink(
            IdentityLinkException ex,
            HttpServletRequest request) {
        log.warn("Account-link rejected: {}, path={}", ex.getMessage(), request.getRequestURI());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.UNPROCESSABLE_ENTITY.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(error);
    }

    /**
     * Phase-5 membership switch refused — the caller tried to assume a membership
     * that does NOT belong to their own platform identity (the same-identity HARD
     * GATE). HTTP 403 Forbidden: this is the ONLY barrier between accounts and is
     * deliberately strict. The message is generic (no membership enumeration).
     */
    @ExceptionHandler(MembershipSwitchForbiddenException.class)
    public ResponseEntity<ErrorResponse> handleMembershipSwitchForbidden(
            MembershipSwitchForbiddenException ex,
            HttpServletRequest request) {
        log.warn("Membership-switch forbidden: {}, path={}", ex.getMessage(), request.getRequestURI());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.FORBIDDEN.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    /**
     * Phase-5 membership switch refused — the same-identity gate passed but the
     * target membership cannot currently be assumed (locked / suspended /
     * inactive / soft-deleted, or its tenant is not ACTIVE). HTTP 409 Conflict:
     * the request was authorized for that account, but the target's current
     * state forbids the switch.
     */
    @ExceptionHandler(MembershipNotSwitchableException.class)
    public ResponseEntity<ErrorResponse> handleMembershipNotSwitchable(
            MembershipNotSwitchableException ex,
            HttpServletRequest request) {
        log.warn("Membership-switch conflict: {}, path={}", ex.getMessage(), request.getRequestURI());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * Self-service onboarding refused: the admin used a personal / free /
     * disposable email provider instead of a corporate domain. HTTP 422
     * Unprocessable Entity. The body carries {@code emailDomain} so the UI can
     * surface a precise message.
     */
    @ExceptionHandler(PersonalEmailNotAllowedException.class)
    public ResponseEntity<java.util.Map<String, Object>> handlePersonalEmailNotAllowed(
            PersonalEmailNotAllowedException ex,
            HttpServletRequest request) {
        log.warn("Onboarding refused — personal/free email domain: {}, path={}",
                ex.getEmailDomain(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.UNPROCESSABLE_ENTITY.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("emailDomain", ex.getEmailDomain());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(body);
    }

    /**
     * Onboarding semantic validation failure (bad slug, undeterminable domain,
     * onboarding disabled). HTTP 400 Bad Request.
     */
    @ExceptionHandler(OnboardingValidationException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleOnboardingValidation(
            OnboardingValidationException ex,
            HttpServletRequest request) {
        log.warn("Onboarding validation failed: {}, path={}", ex.getMessage(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * V62: tenant email-domain registry conflict — either the domain is already
     * claimed by another tenant ({@code EMAIL_DOMAIN_ALREADY_CLAIMED}) or it is
     * the tenant's last domain while enforcement is on
     * ({@code CANNOT_REMOVE_LAST_DOMAIN}). Mapped to HTTP 409 Conflict so the
     * raw unique-index violation never surfaces as a 500.
     */
    @ExceptionHandler(TenantEmailDomainConflictException.class)
    public ResponseEntity<ErrorResponse> handleTenantEmailDomainConflict(
            TenantEmailDomainConflictException ex,
            HttpServletRequest request) {
        log.warn("Tenant email-domain conflict ({}): {}", ex.getErrorCode(), ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * P0-#8 (INVESTIGATION_MASTER_2026-05-07): tenant suspended / inactive /
     * pending. Mapped to HTTP 423 Locked — mirrors {@link AccountLockedException}
     * (the resource is intact but temporarily inaccessible). The body carries
     * the {@link com.fivucsas.identity.entity.TenantStatus} enum value as a
     * string so the frontend / operator tooling can branch on
     * {@code SUSPENDED} vs {@code INACTIVE} vs {@code PENDING}.
     *
     * <pre>
     * {
     *   "timestamp": "...",
     *   "status": 423,
     *   "error": "TENANT_SUSPENDED",
     *   "errorCode": "TENANT_SUSPENDED",
     *   "message": "Tenant is currently SUSPENDED and cannot authenticate users",
     *   "tenantStatus": "SUSPENDED",
     *   "path": "/api/v1/auth/login"
     * }
     * </pre>
     */
    @ExceptionHandler(TenantSuspendedException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleTenantSuspended(
            TenantSuspendedException ex,
            HttpServletRequest request) {
        log.warn("Auth refused — tenant not active: status={}, path={}",
                ex.getStatus(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.LOCKED.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("tenantStatus", ex.getStatus() != null ? ex.getStatus().name() : null);
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.LOCKED).body(body);
    }

    @ExceptionHandler({TokenExpiredException.class, TokenRevokedException.class})
    public ResponseEntity<ErrorResponse> handleTokenException(
            DomainException ex,
            HttpServletRequest request) {
        log.warn("Token exception: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(
            UnauthorizedException ex,
            HttpServletRequest request) {
        log.warn("Unauthorized access: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.FORBIDDEN.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler({BiometricEnrollmentException.class, BiometricVerificationException.class})
    public ResponseEntity<ErrorResponse> handleBiometricException(
            DomainException ex,
            HttpServletRequest request) {
        log.error("Biometric operation failed: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(BiometricNotEnrolledException.class)
    public ResponseEntity<ErrorResponse> handleBiometricNotEnrolled(
            BiometricNotEnrolledException ex,
            HttpServletRequest request) {
        log.warn("Biometric not enrolled: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.PRECONDITION_FAILED.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.PRECONDITION_FAILED).body(error);
    }

    /**
     * Post-audit 2026-04-24 login edge case #5. Returns a bespoke JSON body
     * carrying {@code method} + {@code enrollmentUrl} alongside the standard
     * error envelope — the frontend depends on these to route the user to the
     * correct enrollment screen.
     */
    @ExceptionHandler(NeedsEnrollmentException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleNeedsEnrollment(
            NeedsEnrollmentException ex,
            HttpServletRequest request) {
        log.warn("Login blocked — user needs to enroll: method={}, path={}",
                ex.getMethod(), request.getRequestURI());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", ex.getErrorCode());
        body.put("message", ex.getMessage());
        body.put("method", ex.getMethod());
        body.put("enrollmentUrl", ex.getEnrollmentUrl());
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler({DuplicateRoleException.class, DuplicateRoleAssignmentException.class, DuplicateTenantException.class})
    public ResponseEntity<ErrorResponse> handleDuplicateResource(
            DomainException ex,
            HttpServletRequest request) {
        log.warn("Duplicate resource: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    @ExceptionHandler({RoleNotFoundException.class, PermissionNotFoundException.class, TenantNotFoundException.class})
    public ResponseEntity<ErrorResponse> handleDomainNotFound(
            DomainException ex,
            HttpServletRequest request) {
        log.warn("Domain resource not found: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.NOT_FOUND.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    @ExceptionHandler(SystemRoleModificationException.class)
    public ResponseEntity<ErrorResponse> handleSystemRoleModification(
            SystemRoleModificationException ex,
            HttpServletRequest request) {
        log.warn("System role modification attempted: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.FORBIDDEN.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(InvalidEmailException.class)
    public ResponseEntity<ErrorResponse> handleInvalidEmail(
            InvalidEmailException ex,
            HttpServletRequest request) {
        log.warn("Invalid email: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(
            ResourceNotFoundException ex,
            HttpServletRequest request) {
        log.warn("Resource not found: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.NOT_FOUND.value(),
                "Not Found",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * Password-policy violation: surface the stable error code + a
     * machine-readable list of violation keys so the frontend can render
     * each via i18n (errors.password.<KEY>) without parsing English copy.
     *
     * <p>INVESTIGATION_MASTER_2026-05-07 §"user constraints":
     * the legacy shape concatenated English from PasswordPolicy.java:69 and
     * Turkish-locale users saw raw English. Now: errorCode is stable,
     * details.violations is the i18n key list.</p>
     */
    /**
     * Per-user device-cap exceeded: 409 Conflict with a structured details
     * block carrying the cap and current count so the SPA can prompt the
     * user to remove an existing device. The user-facing copy is rendered
     * via i18n keyed off {@code errorCode = DEVICE_LIMIT_EXCEEDED};
     * {@code message} is short English for log greppability.
     *
     * <p>INVESTIGATION_MASTER_2026-05-07 §"user constraints":
     * "device count per user unbounded → bloated WebAuthn allowList".</p>
     */
    @ExceptionHandler(DeviceLimitExceededException.class)
    public ResponseEntity<java.util.Map<String, Object>> handleDeviceLimit(
            DeviceLimitExceededException ex,
            HttpServletRequest request) {
        log.warn("Device limit exceeded: current={}, max={}",
                ex.getCurrentDevices(), ex.getMaxDevices());

        java.util.Map<String, Object> details = new java.util.LinkedHashMap<>();
        details.put("currentDevices", ex.getCurrentDevices());
        details.put("maxDevices", ex.getMaxDevices());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.CONFLICT.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        body.put("message", "Device registration refused — per-user device cap reached");
        body.put("details", details);
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    @ExceptionHandler(PasswordPolicyViolationException.class)
    public ResponseEntity<java.util.Map<String, Object>> handlePasswordPolicy(
            PasswordPolicyViolationException ex,
            HttpServletRequest request) {
        log.warn("Password policy violation: keys={}", ex.getViolationKeys());

        java.util.Map<String, Object> details = new java.util.LinkedHashMap<>();
        details.put("violations", ex.getViolationKeys());

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("timestamp", java.time.Instant.now().toString());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", ex.getErrorCode());
        body.put("errorCode", ex.getErrorCode());
        // Stable English short-string for log greppability — frontend MUST
        // render UI copy from details.violations via i18n keys, not from
        // this field. Kept short and locale-neutral.
        body.put("message", "Password does not meet policy requirements");
        body.put("details", details);
        body.put("path", request.getRequestURI());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request) {
        log.warn("Bad request: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    /**
     * Domain "state conflict" — e.g. invitation already exists, attempt to
     * accept an expired invite, retry a non-failed enrollment, etc. Maps to
     * HTTP 409 Conflict so the UI can show a meaningful message instead of a
     * generic 500.
     *
     * <p>Copilot post-merge round 5: narrowed from
     * {@link IllegalStateException} (which is also thrown for internal/server
     * faults like crypto/key loading, missing JWT claims, and tenant context
     * errors) to a dedicated {@link DomainStateConflictException}. Generic
     * {@code IllegalStateException} now falls through to the default 500
     * handler so operational issues are not silently masked as 409s.</p>
     */
    @ExceptionHandler(DomainStateConflictException.class)
    public ResponseEntity<ErrorResponse> handleDomainStateConflict(
            DomainStateConflictException ex,
            HttpServletRequest request) {
        log.warn("State conflict: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                "Conflict",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleRateLimitExceeded(
            RateLimitExceededException ex,
            HttpServletRequest request) {
        log.warn("Rate limit exceeded for: {}", request.getRemoteAddr());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Rate Limit Exceeded",
                ex.getMessage(),
                request.getRequestURI()
        );

        // RFC 6585 §4: 429 responses SHOULD include Retry-After. The interceptor
        // already sets it on the raw response, but Spring's ResponseEntity build
        // path here overwrites headers — re-attach it from the exception payload.
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
                .body(error);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request) {
        log.warn("Access denied for: {} - {}", request.getRequestURI(), ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.FORBIDDEN.value(),
                "Access Denied",
                "You don't have permission to access this resource.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex,
            HttpServletRequest request) {
        log.warn("Authentication failed: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                "Authentication Failed",
                "Invalid or expired authentication credentials.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {
        log.warn("Validation failed: {}", ex.getMessage());
        
        List<String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.toList());
        
        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                errors,
                request.getRequestURI()
        );
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    /**
     * Bean Validation failures on @Validated controller method parameters
     * (e.g. {@code @Min}/{@code @Max} on {@code @RequestParam}). Without this
     * handler the default Spring path returns 500 and leaks the violation
     * detail. We surface a clean 400 with the property+message pairs so
     * clients can distinguish caller error from server fault. Closes
     * AUDIT_2026-04-28_EDGE.md finding #4 for the audit-logs endpoint.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(
            ConstraintViolationException ex,
            HttpServletRequest request) {
        log.warn("Parameter validation failed: {}", ex.getMessage());

        List<String> errors = ex.getConstraintViolations().stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .collect(Collectors.toList());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                errors,
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex,
            HttpServletRequest request) {
        log.warn("Malformed request body: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                "Malformed JSON request body.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex,
            HttpServletRequest request) {
        log.warn("Unsupported media type: {}", ex.getContentType());

        String message = "Content type '" + ex.getContentType() + "' is not supported. Expected 'application/json'.";

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.UNSUPPORTED_MEDIA_TYPE.value(),
                "Unsupported Media Type",
                message,
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(error);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotAllowed(
            HttpRequestMethodNotSupportedException ex,
            HttpServletRequest request) {
        log.warn("Method not allowed: {} {}", ex.getMethod(), request.getRequestURI());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.METHOD_NOT_ALLOWED.value(),
                "Method Not Allowed",
                "HTTP method '" + ex.getMethod() + "' is not supported for this endpoint.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(error);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingParameter(
            MissingServletRequestParameterException ex,
            HttpServletRequest request) {
        log.warn("Missing request parameter: {}", ex.getParameterName());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                "Required parameter '" + ex.getParameterName() + "' is missing.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex,
            HttpServletRequest request) {
        log.warn("Type mismatch for parameter '{}': {}", ex.getName(), ex.getMessage());

        String message = "Parameter '" + ex.getName() + "' must be of type " +
                (ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown") + ".";

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                message,
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> handleMaxUploadSizeExceeded(
            MaxUploadSizeExceededException ex,
            HttpServletRequest request) {
        log.warn("File upload size exceeded: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.PAYLOAD_TOO_LARGE.value(),
                "Payload Too Large",
                "Uploaded file exceeds the maximum allowed size.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(error);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request) {
        log.error("Unexpected error occurred", ex);

        ErrorResponse error = ErrorResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "An unexpected error occurred. Please try again later.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
