package com.fivucsas.identity.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * USER-BUG-4 follow-up: the strict E.164 {@link jakarta.validation.constraints.Pattern}
 * on {@code phoneNumber} is the controller's last line of defense against
 * Twilio Verify's send/verify byte-mismatch (where {@code 5551234567}
 * sends to {@code +905551234567} but verifies against the raw stored
 * string). This test pins the regex so a future "loosen the validation"
 * PR cannot silently re-open the bug.
 *
 * <p>Regex assertion: {@code ^\+[1-9]\d{9,14}$} — same as the
 * {@code PhoneNumber} value-object so DTO and domain layer agree.
 */
@DisplayName("Phone number E.164 validation (DTO layer)")
class PhoneNumberValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setupValidator() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void closeFactory() {
        factory.close();
    }

    @Nested
    @DisplayName("UpdateUserRequest")
    class UpdateUser {

        @ParameterizedTest(name = "valid: {0}")
        @ValueSource(strings = {
                "+905551234567",   // TR mobile
                "+12025551234",    // US
                "+447911123456",   // UK
                "+8612345678901"   // CN
        })
        @DisplayName("Accepts E.164 phone numbers")
        void acceptsE164(String phone) {
            UpdateUserRequest req = UpdateUserRequest.builder()
                    .firstName("Ali")
                    .lastName("Veli")
                    .phoneNumber(phone)
                    .build();

            Set<ConstraintViolation<UpdateUserRequest>> violations = validator.validate(req);

            assertThat(violations)
                    .filteredOn(v -> v.getPropertyPath().toString().equals("phoneNumber"))
                    .as("E.164 input %s must validate", phone)
                    .isEmpty();
        }

        @ParameterizedTest(name = "rejects: {0}")
        @ValueSource(strings = {
                "5551234567",       // TR 10-digit no plus, USER-BUG-4 root cause
                "05551234567",      // TR 11-digit with leading 0
                "+0987654321",      // country code starting with 0
                "+1",               // too short
                "+12345678901234567890",   // too long
                "+90 555 123 4567", // contains spaces
                "905551234567",     // missing +
                "abcdefg",          // gibberish
                "+",                // just plus
                "+90555123456a"     // letter mid-string
        })
        @DisplayName("Rejects non-E.164 phone numbers")
        void rejectsNonE164(String phone) {
            UpdateUserRequest req = UpdateUserRequest.builder()
                    .firstName("Ali")
                    .lastName("Veli")
                    .phoneNumber(phone)
                    .build();

            Set<ConstraintViolation<UpdateUserRequest>> violations = validator.validate(req);

            assertThat(violations)
                    .filteredOn(v -> v.getPropertyPath().toString().equals("phoneNumber"))
                    .as("non-E.164 input %s must violate the @Pattern", phone)
                    .isNotEmpty()
                    .extracting(ConstraintViolation::getMessage)
                    .allSatisfy(msg ->
                            assertThat(msg).contains("phone.e164"));
        }

        @ParameterizedTest
        @NullSource
        @DisplayName("Accepts null (phone is optional on update)")
        void acceptsNull(String phone) {
            UpdateUserRequest req = UpdateUserRequest.builder()
                    .firstName("Ali")
                    .lastName("Veli")
                    .phoneNumber(phone)
                    .build();

            Set<ConstraintViolation<UpdateUserRequest>> violations = validator.validate(req);

            assertThat(violations)
                    .filteredOn(v -> v.getPropertyPath().toString().equals("phoneNumber"))
                    .as("null must NOT violate (optional field — Bean Validation @Pattern skips null by spec)")
                    .isEmpty();
        }
    }

    @Nested
    @DisplayName("CreateUserRequest")
    class CreateUser {

        @Test
        @DisplayName("Accepts E.164 phone")
        void acceptsE164() {
            CreateUserRequest req = CreateUserRequest.builder()
                    .firstName("Ali")
                    .lastName("Veli")
                    .email("a@b.com")
                    .password("Password123!")
                    .phoneNumber("+905551234567")
                    .build();

            Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(req);

            assertThat(violations)
                    .filteredOn(v -> v.getPropertyPath().toString().equals("phoneNumber"))
                    .isEmpty();
        }

        @Test
        @DisplayName("Rejects bare 10-digit (USER-BUG-4 root cause)")
        void rejectsBareTenDigit() {
            CreateUserRequest req = CreateUserRequest.builder()
                    .firstName("Ali")
                    .lastName("Veli")
                    .email("a@b.com")
                    .password("Password123!")
                    .phoneNumber("5551234567")
                    .build();

            Set<ConstraintViolation<CreateUserRequest>> violations = validator.validate(req);

            assertThat(violations)
                    .filteredOn(v -> v.getPropertyPath().toString().equals("phoneNumber"))
                    .isNotEmpty()
                    .extracting(ConstraintViolation::getMessage)
                    .allSatisfy(msg -> assertThat(msg).contains("phone.e164"));
        }
    }
}
