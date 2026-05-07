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
