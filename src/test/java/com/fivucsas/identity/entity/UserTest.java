package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.user.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for User entity business methods.
 * Tests the Rich Domain Model behavior.
 */
class UserTest {

    private PasswordEncoder passwordEncoder;
    private User user;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();

        // Create test user using builder
        user = User.builder()
            .email("john.doe@example.com")
            .passwordHash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy") // hashed "password123"
            .firstName("John")
            .lastName("Doe")
            .phoneNumber("+905551234567")
            .address("123 Main Street")
            .idNumber("12345678910")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .build();
    }

    // ========== Value Object Getters Tests ==========

    @Test
    void shouldReturnEmailAsValueObject() {
        // When
        Email email = user.getEmailAsValueObject();

        // Then
        assertNotNull(email);
        assertEquals("john.doe@example.com", email.getValue());
    }

    @Test
    void shouldReturnNullEmailAsValueObjectWhenNull() {
        // Given
        User userWithoutEmail = User.builder()
            .firstName("Jane")
            .lastName("Doe")
            .build();

        // When
        Email email = userWithoutEmail.getEmailAsValueObject();

        // Then
        assertNull(email);
    }

    @Test
    void shouldReturnPasswordAsValueObject() {
        // When
        HashedPassword password = user.getPasswordAsValueObject();

        // Then
        assertNotNull(password);
        assertEquals("[PROTECTED]", password.toString()); // Never expose hash
    }

    @Test
    void shouldReturnPhoneNumberAsValueObject() {
        // When
        PhoneNumber phone = user.getPhoneNumberAsValueObject();

        // Then
        assertNotNull(phone);
        assertEquals("+905551234567", phone.getValue());
    }

    @Test
    void shouldReturnAddressAsValueObject() {
        // When
        Address address = user.getAddressAsValueObject();

        // Then
        assertNotNull(address);
        assertEquals("123 Main Street", address.getValue());
    }

    @Test
    void shouldReturnIdNumberAsValueObject() {
        // When
        IdNumber idNumber = user.getIdNumberAsValueObject();

        // Then
        assertNotNull(idNumber);
        assertEquals("12345678910", idNumber.getValue());
        assertEquals("12345***910", idNumber.getMasked()); // Masked representation
    }

    @Test
    void shouldReturnFullNameAsValueObject() {
        // When
        FullName fullName = user.getFullNameAsValueObject();

        // Then
        assertNotNull(fullName);
        assertEquals("John", fullName.getFirstName());
        assertEquals("Doe", fullName.getLastName());
        assertEquals("John Doe", fullName.getFullName());
    }

    @Test
    void shouldReturnNullFullNameWhenFirstNameNull() {
        // Given
        User userWithoutName = User.builder()
            .email("test@example.com")
            .lastName("Doe")
            .build();

        // When
        FullName fullName = userWithoutName.getFullNameAsValueObject();

        // Then
        assertNull(fullName);
    }

    // ========== Business Methods Tests ==========

    @Test
    void shouldGetFullNameAsString() {
        // When
        String fullName = user.getFullName();

        // Then
        assertEquals("John Doe", fullName);
    }

    @Test
    void shouldReturnEmptyStringForFullNameWhenNull() {
        // Given
        User userWithoutName = User.builder()
            .email("test@example.com")
            .build();

        // When
        String fullName = userWithoutName.getFullName();

        // Then
        assertEquals("", fullName);
    }

    @Test
    void shouldChangeEmail() {
        // Given
        Email newEmail = Email.of("new.email@example.com");

        // When
        user.changeEmail(newEmail);

        // Then
        assertEquals("new.email@example.com", user.getEmail());
        assertEquals(newEmail, user.getEmailAsValueObject());
    }

    @Test
    void shouldRejectNullEmailChange() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> user.changeEmail(null)
        );
        assertEquals("Email cannot be null", exception.getMessage());
    }

    @Test
    void shouldUpdatePassword() {
        // Given
        String newPlainPassword = "newPassword123";

        // When
        user.updatePassword(newPlainPassword, passwordEncoder);

        // Then
        assertNotNull(user.getPasswordHash());
        assertTrue(user.getPasswordHash().startsWith("$2")); // BCrypt prefix
        assertEquals(60, user.getPasswordHash().length()); // BCrypt length

        // Verify the password was actually hashed correctly
        assertTrue(passwordEncoder.matches(newPlainPassword, user.getPasswordHash()));
    }

    @Test
    void shouldRejectNullPassword() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> user.updatePassword(null, passwordEncoder)
        );
        assertEquals("Password cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectEmptyPassword() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> user.updatePassword("", passwordEncoder)
        );
        assertEquals("Password cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectPasswordTooShort() {
        // Given
        String shortPassword = "1234567"; // 7 characters

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> user.updatePassword(shortPassword, passwordEncoder)
        );
        assertEquals("Password must be at least 8 characters", exception.getMessage());
    }

    @Test
    void shouldCheckPasswordCorrectly() {
        // Given
        String correctPassword = "password123";
        String wrongPassword = "wrongPassword";

        // Update with known password
        user.updatePassword(correctPassword, passwordEncoder);

        // When & Then
        assertTrue(user.checkPassword(correctPassword, passwordEncoder));
        assertFalse(user.checkPassword(wrongPassword, passwordEncoder));
    }

    @Test
    void shouldReturnFalseForNullPasswordCheck() {
        // When & Then
        assertFalse(user.checkPassword(null, passwordEncoder));
    }

    @Test
    void shouldUpdatePhoneNumber() {
        // Given
        PhoneNumber newPhone = PhoneNumber.of("+12025551234");

        // When
        user.updatePhoneNumber(newPhone);

        // Then
        assertEquals("+12025551234", user.getPhoneNumber());
    }

    @Test
    void shouldAllowNullPhoneNumber() {
        // When
        user.updatePhoneNumber(null);

        // Then
        assertNull(user.getPhoneNumber());
    }

    @Test
    void shouldUpdateAddress() {
        // Given
        Address newAddress = Address.of("456 Oak Avenue");

        // When
        user.updateAddress(newAddress);

        // Then
        assertEquals("456 Oak Avenue", user.getAddress());
    }

    @Test
    void shouldAllowNullAddress() {
        // When
        user.updateAddress(null);

        // Then
        assertNull(user.getAddress());
    }

    @Test
    void shouldUpdateIdNumber() {
        // Given
        IdNumber newIdNumber = IdNumber.of("10000000146");

        // When
        user.updateIdNumber(newIdNumber);

        // Then
        assertEquals("10000000146", user.getIdNumber());
    }

    @Test
    void shouldAllowNullIdNumber() {
        // When
        user.updateIdNumber(null);

        // Then
        assertNull(user.getIdNumber());
    }

    @Test
    void shouldUpdateProfile() {
        // Given
        PhoneNumber newPhone = PhoneNumber.of("+12025551234");
        Address newAddress = Address.of("789 Elm Street");

        // When
        user.updateProfile("Jane", "Smith", newPhone, newAddress);

        // Then
        assertEquals("Jane", user.getFirstName());
        assertEquals("Smith", user.getLastName());
        assertEquals("+12025551234", user.getPhoneNumber());
        assertEquals("789 Elm Street", user.getAddress());
        assertEquals("Jane Smith", user.getFullName());
    }

    @Test
    void shouldValidateNamesWhenUpdatingProfile() {
        // Given
        String invalidFirstName = "John123"; // Contains numbers

        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> user.updateProfile(invalidFirstName, "Doe", null, null)
        );
        assertTrue(exception.getMessage().contains("contains invalid characters"));
    }

    @Test
    void shouldEnrollBiometric() {
        // Given
        Instant beforeEnrollment = Instant.now();

        // When
        user.enrollBiometric();

        // Then
        assertTrue(user.isBiometricEnrolled());
        assertNotNull(user.getEnrolledAt());
        assertTrue(user.getEnrolledAt().isAfter(beforeEnrollment) ||
                   user.getEnrolledAt().equals(beforeEnrollment));
    }

    @Test
    void shouldUnenrollBiometric() {
        // Given - User is enrolled
        user.enrollBiometric();
        user.incrementVerificationCount();
        assertTrue(user.isBiometricEnrolled());

        // When
        user.unenrollBiometric();

        // Then
        assertFalse(user.isBiometricEnrolled());
        assertNull(user.getEnrolledAt());
        assertNull(user.getLastVerifiedAt());
        assertEquals(0, user.getVerificationCount());
    }

    @Test
    void shouldIncrementVerificationCount() {
        // Given
        int initialCount = user.getVerificationCount();
        Instant beforeVerification = Instant.now();

        // When
        user.incrementVerificationCount();

        // Then
        assertEquals(initialCount + 1, user.getVerificationCount());
        assertNotNull(user.getLastVerifiedAt());
        assertTrue(user.getLastVerifiedAt().isAfter(beforeVerification) ||
                   user.getLastVerifiedAt().equals(beforeVerification));
    }

    @Test
    void shouldIncrementVerificationCountMultipleTimes() {
        // When
        user.incrementVerificationCount();
        user.incrementVerificationCount();
        user.incrementVerificationCount();

        // Then
        assertEquals(3, user.getVerificationCount());
    }

    @Test
    void shouldActivateUser() {
        // Given
        user.deactivate();
        assertFalse(user.isActive());

        // When
        user.activate();

        // Then
        assertEquals(UserStatus.ACTIVE, user.getStatus());
        assertTrue(user.isActive());
    }

    @Test
    void shouldDeactivateUser() {
        // Given
        assertTrue(user.isActive());

        // When
        user.deactivate();

        // Then
        assertEquals(UserStatus.INACTIVE, user.getStatus());
        assertFalse(user.isActive());
    }

    @Test
    void shouldSuspendUser() {
        // Given
        assertTrue(user.isActive());

        // When
        user.suspend();

        // Then
        assertEquals(UserStatus.SUSPENDED, user.getStatus());
        assertTrue(user.isSuspended());
        assertFalse(user.isActive());
    }

    @Test
    void shouldCheckIfUserIsActive() {
        // Given - User is active by default
        // When & Then
        assertTrue(user.isActive());

        // When
        user.deactivate();

        // Then
        assertFalse(user.isActive());
    }

    @Test
    void shouldCheckIfUserIsSuspended() {
        // Given - User is not suspended by default
        // When & Then
        assertFalse(user.isSuspended());

        // When
        user.suspend();

        // Then
        assertTrue(user.isSuspended());
    }

    @Test
    void shouldCheckIfUserHasBiometricEnrolled() {
        // Given - User is not enrolled by default
        // When & Then
        assertFalse(user.hasBiometricEnrolled());

        // When
        user.enrollBiometric();

        // Then
        assertTrue(user.hasBiometricEnrolled());
    }

    @Test
    void shouldCheckIfUserHasEmail() {
        // Given
        Email sameEmail = Email.of("john.doe@example.com");
        Email differentEmail = Email.of("jane.doe@example.com");

        // When & Then
        assertTrue(user.hasEmail(sameEmail));
        assertFalse(user.hasEmail(differentEmail));
    }

    @Test
    void shouldCheckEmailCaseInsensitively() {
        // Given
        Email uppercaseEmail = Email.of("JOHN.DOE@EXAMPLE.COM");

        // When & Then - Email comparison should be case-insensitive
        assertTrue(user.hasEmail(uppercaseEmail));
    }

    @Test
    void shouldNotThrowWhenCheckingEmailOnUserWithoutEmail() {
        // Given
        User userWithoutEmail = User.builder()
            .firstName("Jane")
            .lastName("Doe")
            .build();
        Email email = Email.of("test@example.com");

        // When & Then - Should not throw, just return false
        assertFalse(userWithoutEmail.hasEmail(email));
    }

    // ========== Email/Phone Verification Tests ==========

    @Test
    void shouldVerifyEmail() {
        // Given - user starts with email unverified
        assertFalse(user.isEmailVerified());

        // When
        user.verifyEmail();

        // Then
        assertTrue(user.isEmailVerified());
    }

    @Test
    void shouldVerifyPhone() {
        // Given - user starts with phone unverified
        assertFalse(user.isPhoneVerified());

        // When
        user.verifyPhone();

        // Then
        assertTrue(user.isPhoneVerified());
    }

    @Test
    void shouldClearVerificationTokenOnEmailVerify() {
        // Given - simulate a user who was built with defaults (emailVerified=false)
        User userWithDefaults = User.builder()
                .email("test@example.com")
                .firstName("Test")
                .lastName("User")
                .build();

        // When
        userWithDefaults.verifyEmail();

        // Then
        assertTrue(userWithDefaults.isEmailVerified());
        assertNull(userWithDefaults.getEmailVerificationToken());
        assertNull(userWithDefaults.getEmailVerificationSentAt());
    }

    // ========== Builder Tests ==========

    @Test
    void shouldBuildUserWithDefaultValues() {
        // When
        User newUser = User.builder()
            .email("test@example.com")
            .firstName("Test")
            .lastName("User")
            .build();

        // Then
        assertEquals(UserStatus.ACTIVE, newUser.getStatus());
        assertFalse(newUser.isBiometricEnrolled());
        assertEquals(0, newUser.getVerificationCount());
    }

    @Test
    void shouldBuildUserWithAllFields() {
        // When
        User newUser = User.builder()
            .email("test@example.com")
            .passwordHash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
            .firstName("Test")
            .lastName("User")
            .phoneNumber("+905551234567")
            .address("Test Address")
            .idNumber("12345678910")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(true)
            .verificationCount(5)
            .build();

        // Then
        assertEquals("test@example.com", newUser.getEmail());
        assertEquals("Test", newUser.getFirstName());
        assertEquals("User", newUser.getLastName());
        assertEquals("+905551234567", newUser.getPhoneNumber());
        assertEquals("Test Address", newUser.getAddress());
        assertEquals("12345678910", newUser.getIdNumber());
        assertEquals(UserStatus.ACTIVE, newUser.getStatus());
        assertTrue(newUser.isBiometricEnrolled());
        assertEquals(5, newUser.getVerificationCount());
    }
}
