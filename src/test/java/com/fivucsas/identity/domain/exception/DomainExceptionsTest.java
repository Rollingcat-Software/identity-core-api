package com.fivucsas.identity.domain.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for all domain exceptions.
 * Tests error codes, messages, and exception hierarchy.
 */
class DomainExceptionsTest {

    // ========== UserNotFoundException Tests ==========

    @Test
    void userNotFoundException_shouldHaveDefaultMessage() {
        // When
        UserNotFoundException exception = new UserNotFoundException();

        // Then
        assertEquals("User not found", exception.getMessage());
        assertEquals("USER_NOT_FOUND", exception.getErrorCode());
    }

    @Test
    void userNotFoundException_shouldIncludeIdentifier() {
        // Given
        String userId = "user-123";

        // When
        UserNotFoundException exception = new UserNotFoundException(userId);

        // Then
        assertEquals("User not found: user-123", exception.getMessage());
        assertEquals("USER_NOT_FOUND", exception.getErrorCode());
    }

    @Test
    void userNotFoundException_shouldWrapCause() {
        // Given
        Throwable cause = new RuntimeException("Database error");

        // When
        UserNotFoundException exception = new UserNotFoundException("User not found", cause);

        // Then
        assertEquals("User not found", exception.getMessage());
        assertEquals("USER_NOT_FOUND", exception.getErrorCode());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void userNotFoundException_shouldExtendDomainException() {
        // When
        UserNotFoundException exception = new UserNotFoundException();

        // Then
        assertTrue(exception instanceof DomainException);
        assertTrue(exception instanceof RuntimeException);
    }

    // ========== InvalidCredentialsException Tests ==========

    @Test
    void invalidCredentialsException_shouldHaveDefaultMessage() {
        // When
        InvalidCredentialsException exception = new InvalidCredentialsException();

        // Then
        assertEquals("Invalid email or password", exception.getMessage());
        assertEquals("INVALID_CREDENTIALS", exception.getErrorCode());
    }

    @Test
    void invalidCredentialsException_shouldAcceptCustomMessage() {
        // When
        InvalidCredentialsException exception = new InvalidCredentialsException("Custom error");

        // Then
        assertEquals("Custom error", exception.getMessage());
        assertEquals("INVALID_CREDENTIALS", exception.getErrorCode());
    }

    @Test
    void invalidCredentialsException_shouldWrapCause() {
        // Given
        Throwable cause = new RuntimeException("Auth service error");

        // When
        InvalidCredentialsException exception = new InvalidCredentialsException("Auth failed", cause);

        // Then
        assertEquals("Auth failed", exception.getMessage());
        assertEquals("INVALID_CREDENTIALS", exception.getErrorCode());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void invalidCredentialsException_shouldNotLeakSensitiveInfo() {
        // When
        InvalidCredentialsException exception = new InvalidCredentialsException();

        // Then - Generic message prevents username enumeration
        assertFalse(exception.getMessage().contains("email"));
        assertFalse(exception.getMessage().toLowerCase().contains("username"));
    }

    // ========== DuplicateEmailException Tests ==========

    @Test
    void duplicateEmailException_shouldIncludeEmail() {
        // Given
        String email = "user@example.com";

        // When
        DuplicateEmailException exception = new DuplicateEmailException(email);

        // Then
        assertTrue(exception.getMessage().contains(email));
        assertEquals("DUPLICATE_EMAIL", exception.getErrorCode());
    }

    @Test
    void duplicateEmailException_shouldExtendDomainException() {
        // When
        DuplicateEmailException exception = new DuplicateEmailException("test@example.com");

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== TokenExpiredException Tests ==========

    @Test
    void tokenExpiredException_shouldHaveDefaultMessage() {
        // When
        TokenExpiredException exception = new TokenExpiredException("Access");

        // Then
        assertTrue(exception.getMessage().contains("Access"));
        assertTrue(exception.getMessage().toLowerCase().contains("expired"));
        assertEquals("TOKEN_EXPIRED", exception.getErrorCode());
    }

    @Test
    void tokenExpiredException_shouldExtendDomainException() {
        // When
        TokenExpiredException exception = new TokenExpiredException("Refresh");

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== TokenRevokedException Tests ==========

    @Test
    void tokenRevokedException_shouldHaveDefaultMessage() {
        // When
        TokenRevokedException exception = new TokenRevokedException();

        // Then
        assertTrue(exception.getMessage().toLowerCase().contains("revoked"));
        assertEquals("TOKEN_REVOKED", exception.getErrorCode());
    }

    @Test
    void tokenRevokedException_shouldAcceptCustomMessage() {
        // When
        TokenRevokedException exception = new TokenRevokedException("Custom revoked message");

        // Then
        assertEquals("Custom revoked message", exception.getMessage());
        assertEquals("TOKEN_REVOKED", exception.getErrorCode());
    }

    @Test
    void tokenRevokedException_shouldExtendDomainException() {
        // When
        TokenRevokedException exception = new TokenRevokedException();

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== UnauthorizedException Tests ==========

    @Test
    void unauthorizedException_shouldHaveDefaultMessage() {
        // When
        UnauthorizedException exception = new UnauthorizedException();

        // Then
        assertTrue(exception.getMessage().toLowerCase().contains("unauthorized") ||
                   exception.getMessage().toLowerCase().contains("access denied"));
        assertEquals("UNAUTHORIZED", exception.getErrorCode());
    }

    @Test
    void unauthorizedException_shouldAcceptCustomMessage() {
        // When
        UnauthorizedException exception = new UnauthorizedException("Permission denied");

        // Then
        assertEquals("Permission denied", exception.getMessage());
        assertEquals("UNAUTHORIZED", exception.getErrorCode());
    }

    @Test
    void unauthorizedException_shouldExtendDomainException() {
        // When
        UnauthorizedException exception = new UnauthorizedException();

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== BiometricEnrollmentException Tests ==========

    @Test
    void biometricEnrollmentException_shouldHaveMessage() {
        // When
        BiometricEnrollmentException exception = new BiometricEnrollmentException("Enrollment failed");

        // Then
        assertEquals("Enrollment failed", exception.getMessage());
        assertEquals("BIOMETRIC_ENROLLMENT_FAILED", exception.getErrorCode());
    }

    @Test
    void biometricEnrollmentException_shouldWrapCause() {
        // Given
        Throwable cause = new RuntimeException("Face detection failed");

        // When
        BiometricEnrollmentException exception = new BiometricEnrollmentException("Enrollment failed", cause);

        // Then
        assertEquals("Enrollment failed", exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void biometricEnrollmentException_shouldExtendDomainException() {
        // When
        BiometricEnrollmentException exception = new BiometricEnrollmentException("Test");

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== BiometricVerificationException Tests ==========

    @Test
    void biometricVerificationException_shouldHaveMessage() {
        // When
        BiometricVerificationException exception = new BiometricVerificationException("Verification failed");

        // Then
        assertEquals("Verification failed", exception.getMessage());
        assertEquals("BIOMETRIC_VERIFICATION_FAILED", exception.getErrorCode());
    }

    @Test
    void biometricVerificationException_shouldWrapCause() {
        // Given
        Throwable cause = new RuntimeException("Face match failed");

        // When
        BiometricVerificationException exception = new BiometricVerificationException("Verification failed", cause);

        // Then
        assertEquals("Verification failed", exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void biometricVerificationException_shouldExtendDomainException() {
        // When
        BiometricVerificationException exception = new BiometricVerificationException("Test");

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== BiometricNotEnrolledException Tests ==========

    @Test
    void biometricNotEnrolledException_shouldIncludeUserId() {
        // Given
        String userId = "user-123";

        // When
        BiometricNotEnrolledException exception = new BiometricNotEnrolledException(userId);

        // Then
        assertTrue(exception.getMessage().contains(userId));
        assertTrue(exception.getMessage().toLowerCase().contains("not enrolled") ||
                   exception.getMessage().toLowerCase().contains("no biometric"));
        assertEquals("BIOMETRIC_NOT_ENROLLED", exception.getErrorCode());
    }

    @Test
    void biometricNotEnrolledException_shouldExtendDomainException() {
        // When
        BiometricNotEnrolledException exception = new BiometricNotEnrolledException("user-123");

        // Then
        assertTrue(exception instanceof DomainException);
    }

    // ========== DomainException Base Class Tests ==========

    @Test
    void domainException_shouldProvideErrorCode() {
        // Given - Create concrete implementation
        UserNotFoundException exception = new UserNotFoundException();

        // When
        String errorCode = exception.getErrorCode();

        // Then
        assertNotNull(errorCode);
        assertFalse(errorCode.isEmpty());
    }

    @Test
    void domainException_shouldBeRuntimeException() {
        // Given
        DomainException exception = new UserNotFoundException();

        // Then
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void domainException_errorCodesShouldBeUnique() {
        // Create all exception types
        UserNotFoundException userNotFound = new UserNotFoundException();
        InvalidCredentialsException invalidCreds = new InvalidCredentialsException();
        DuplicateEmailException duplicateEmail = new DuplicateEmailException("test@example.com");
        TokenExpiredException tokenExpired = new TokenExpiredException("Access");
        TokenRevokedException tokenRevoked = new TokenRevokedException();
        UnauthorizedException unauthorized = new UnauthorizedException();
        BiometricEnrollmentException bioEnroll = new BiometricEnrollmentException("Test");
        BiometricVerificationException bioVerify = new BiometricVerificationException("Test");
        BiometricNotEnrolledException bioNotEnrolled = new BiometricNotEnrolledException("user-123");

        // Then - All error codes should be unique
        assertEquals("USER_NOT_FOUND", userNotFound.getErrorCode());
        assertEquals("INVALID_CREDENTIALS", invalidCreds.getErrorCode());
        assertEquals("DUPLICATE_EMAIL", duplicateEmail.getErrorCode());
        assertEquals("TOKEN_EXPIRED", tokenExpired.getErrorCode());
        assertEquals("TOKEN_REVOKED", tokenRevoked.getErrorCode());
        assertEquals("UNAUTHORIZED", unauthorized.getErrorCode());
        assertEquals("BIOMETRIC_ENROLLMENT_FAILED", bioEnroll.getErrorCode());
        assertEquals("BIOMETRIC_VERIFICATION_FAILED", bioVerify.getErrorCode());
        assertEquals("BIOMETRIC_NOT_ENROLLED", bioNotEnrolled.getErrorCode());
    }

    @Test
    void domainException_shouldPreserveStackTrace() {
        // When
        UserNotFoundException exception = new UserNotFoundException("test");

        // Then
        assertNotNull(exception.getStackTrace());
        assertTrue(exception.getStackTrace().length > 0);
    }

    @Test
    void domainException_shouldSupportCauseChaining() {
        // Given
        RuntimeException rootCause = new RuntimeException("Root cause");
        IllegalStateException intermediateCause = new IllegalStateException("Intermediate", rootCause);

        // When
        UserNotFoundException exception = new UserNotFoundException("User error", intermediateCause);

        // Then
        assertEquals(intermediateCause, exception.getCause());
        assertEquals(rootCause, exception.getCause().getCause());
    }
}
