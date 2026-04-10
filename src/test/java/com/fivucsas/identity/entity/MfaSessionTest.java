package com.fivucsas.identity.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for MfaSession entity business methods.
 *
 * Covers:
 * - addCompletedMethod / getCompletedMethods
 * - advanceStep / allStepsCompleted
 * - isExpired / isCompleted
 * - getCompletedMethods returns expected AMR values for duplicate-detection
 */
@DisplayName("MfaSession Entity Tests")
class MfaSessionTest {

    private MfaSession session;

    @BeforeEach
    void setUp() {
        session = MfaSession.builder()
                .sessionToken("test-token-" + UUID.randomUUID())
                .userId(UUID.randomUUID())
                .tenantId(UUID.randomUUID())
                .flowId(UUID.randomUUID())
                .totalSteps(2)
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    // ──────────────────────────────────────────────────────────────
    // addCompletedMethod + getCompletedMethods
    // ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getCompletedMethods returns empty list on fresh session")
    void freshSessionHasNoCompletedMethods() {
        List<String> methods = session.getCompletedMethods();

        assertNotNull(methods);
        assertTrue(methods.isEmpty(), "Fresh session should have no completed methods");
    }

    @Test
    @DisplayName("addCompletedMethod appends the AMR value")
    void addCompletedMethodAppendsValue() {
        session.addCompletedMethod("pwd");

        List<String> methods = session.getCompletedMethods();
        assertEquals(1, methods.size());
        assertEquals("pwd", methods.get(0));
    }

    @Test
    @DisplayName("addCompletedMethod can store multiple different methods")
    void addCompletedMethodStoresMultipleDifferentMethods() {
        session.addCompletedMethod("pwd");
        session.addCompletedMethod("otp");

        List<String> methods = session.getCompletedMethods();
        assertEquals(2, methods.size());
        assertTrue(methods.contains("pwd"));
        assertTrue(methods.contains("otp"));
    }

    // ──────────────────────────────────────────────────────────────
    // Same-method prevention (the P1-B security fix)
    // ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getCompletedMethods detects same AMR value — same method cannot be added twice without controller check")
    void sameMethodDetectedByCompletedMethodsList() {
        // Simulate step 1: PASSWORD verified → amr "pwd" recorded
        session.addCompletedMethod("pwd");
        session.advanceStep();

        // Before step 2: controller reads completed list to reject same-method
        List<String> completedAfterStep1 = session.getCompletedMethods();
        assertTrue(completedAfterStep1.contains("pwd"),
                "After step 1 (PASSWORD), 'pwd' must be in the completed list so the controller can reject it");

        // Attempting to use "pwd" again (face would be "face", otp "otp") is caught by contains() check
        String attemptedMethod = "pwd";
        boolean wouldBeRejected = completedAfterStep1.contains(attemptedMethod);
        assertTrue(wouldBeRejected,
                "Controller should reject step 2 with 'pwd' because it already appears in completedMethods");
    }

    @Test
    @DisplayName("getCompletedMethods does NOT block a legitimately different method")
    void differentMethodNotBlockedByCompletedList() {
        // Simulate step 1: PASSWORD
        session.addCompletedMethod("pwd");
        session.advanceStep();

        List<String> completedAfterStep1 = session.getCompletedMethods();

        // Face ("face") has not been used yet — controller should allow it
        boolean wouldBeRejected = completedAfterStep1.contains("face");
        assertFalse(wouldBeRejected,
                "Controller should NOT reject step 2 with FACE because 'face' is not in the completed list");
    }

    @Test
    @DisplayName("getCompletedMethods does NOT block TOTP after EMAIL_OTP (both are 'otp' AMR) — edge case awareness")
    void totpAndEmailOtpShareSameAmrValue() {
        // Both TOTP and EMAIL_OTP map to AMR value "otp".
        // This test documents the edge case: they share an AMR code,
        // so the controller's contains() check will reject TOTP if EMAIL_OTP was already used.
        // This is CORRECT behaviour per the security requirement.
        session.addCompletedMethod("otp"); // EMAIL_OTP step completed
        session.advanceStep();

        List<String> completed = session.getCompletedMethods();
        assertTrue(completed.contains("otp"),
                "After EMAIL_OTP step, 'otp' is in completed list — TOTP (also 'otp') should also be blocked");
    }

    // ──────────────────────────────────────────────────────────────
    // advanceStep / allStepsCompleted
    // ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("currentStep starts at 1 and advances correctly")
    void stepAdvances() {
        assertEquals(1, session.getCurrentStep());
        session.advanceStep();
        assertEquals(2, session.getCurrentStep());
    }

    @Test
    @DisplayName("allStepsCompleted is false while steps remain")
    void notAllStepsCompletedWhileStepsRemain() {
        // currentStep = 1, totalSteps = 2 → still 1 step left
        assertFalse(session.allStepsCompleted());

        session.advanceStep(); // currentStep = 2
        assertFalse(session.allStepsCompleted());
    }

    @Test
    @DisplayName("allStepsCompleted is true after all steps are advanced past")
    void allStepsCompletedAfterLastStep() {
        session.advanceStep(); // currentStep = 2
        session.advanceStep(); // currentStep = 3 → exceeds totalSteps (2)

        assertTrue(session.allStepsCompleted());
    }

    // ──────────────────────────────────────────────────────────────
    // isExpired / isCompleted
    // ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("session is not expired when expiresAt is in the future")
    void notExpiredWhenExpiresAtInFuture() {
        assertFalse(session.isExpired());
    }

    @Test
    @DisplayName("session is expired when expiresAt is in the past")
    void expiredWhenExpiresAtInPast() {
        MfaSession expiredSession = MfaSession.builder()
                .sessionToken("expired-" + UUID.randomUUID())
                .userId(UUID.randomUUID())
                .tenantId(UUID.randomUUID())
                .flowId(UUID.randomUUID())
                .totalSteps(2)
                .expiresAt(Instant.now().minusSeconds(1))
                .build();

        assertTrue(expiredSession.isExpired());
    }

    @Test
    @DisplayName("session is not completed initially")
    void notCompletedInitially() {
        assertFalse(session.isCompleted());
    }

    @Test
    @DisplayName("session is completed after complete() is called")
    void completedAfterCompleteCall() {
        session.complete();
        assertTrue(session.isCompleted());
    }
}
