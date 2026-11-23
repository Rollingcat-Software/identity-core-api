package com.fivucsas.identity.application.service.mfa;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The reasons are written to the security audit log and queried by name, so their
 * values are a contract. Code and the other tests use the constants; this test is
 * the one place that pins the wire values, so a rename fails here.
 */
class MfaFailureReasonsTest {

    @Test
    @DisplayName("Face reasons keep their audit-log values")
    void faceReasons_WhenRead_ShouldKeepTheirAuditLogValues() {
        assertThat(MfaFailureReasons.FACE_MISMATCH).isEqualTo("face_mismatch");
        assertThat(MfaFailureReasons.FACE_SPOOF_DETECTED).isEqualTo("face_spoof_detected");
        assertThat(MfaFailureReasons.FACE_VERIFIER_NO_VERDICT).isEqualTo("face_verifier_no_verdict");
        assertThat(MfaFailureReasons.MISSING_FACE_IMAGE).isEqualTo("missing_face_image");
        assertThat(MfaFailureReasons.FACE_VERIFICATION_FAILED).isEqualTo("face_verification_failed");
    }

    @Test
    @DisplayName("Every reason is the lower-case form of its constant name and unique")
    void allReasons_WhenListed_ShouldMatchTheirConstantNameAndBeUnique() throws IllegalAccessException {
        List<Field> fields = Arrays.stream(MfaFailureReasons.class.getDeclaredFields())
                .filter(f -> Modifier.isStatic(f.getModifiers()) && f.getType() == String.class)
                .toList();
        assertThat(fields).hasSizeGreaterThanOrEqualTo(20);
        List<String> values = new java.util.ArrayList<>();
        for (Field field : fields) {
            String value = (String) field.get(null);
            assertThat(value).isEqualTo(field.getName().toLowerCase(java.util.Locale.ROOT));
            values.add(value);
        }
        assertThat(values).doesNotHaveDuplicates();
    }
}
