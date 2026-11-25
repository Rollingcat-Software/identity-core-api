package com.fivucsas.identity.application.service.authorTrial;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("AuthorTrialInputSanitizer — hostile public payloads")
class AuthorTrialInputSanitizerTest {

    private final AuthorTrialInputSanitizer sanitizer = new AuthorTrialInputSanitizer(new ObjectMapper());
    private final ObjectMapper mapper = new ObjectMapper();

    private ObjectNode obj() {
        return mapper.createObjectNode();
    }

    @Test
    void device_KeepsOnlyAllowListedScalars() {
        ObjectNode raw = obj();
        raw.put("label", "HP Victus");
        raw.put("os", "Windows");
        raw.put("browser", "Chrome");
        raw.put("screen", "1920x1080@1");
        raw.put("cameraLabel", "HD Webcam");
        raw.put("cameraResolution", "1280x720");
        raw.put("hardwareConcurrency", 8);
        raw.put("deviceMemoryGB", 16);
        raw.put("userAgent", "Mozilla/5.0");
        raw.put("secret", "do-not-store");
        raw.putObject("nested").put("x", 1);

        AuthorTrialInputSanitizer.SanitizedJson out = sanitizer.device(raw, 4096);

        assertThat(out.json()).contains("\"label\":\"HP Victus\"");
        assertThat(out.json()).contains("\"cameraResolution\":\"1280x720\"");
        assertThat(out.json()).doesNotContain("secret");
        assertThat(out.json()).doesNotContain("nested");
        assertThat(out.bytes()).isEqualTo(out.json().getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
    }

    @Test
    void device_StripsControlCharactersAndCapsLength() {
        ObjectNode raw = obj();
        raw.put("label", "A\u0000B\nC" + "x".repeat(200));
        raw.put("cameraResolution", "not-a-resolution");

        AuthorTrialInputSanitizer.SanitizedJson out = sanitizer.device(raw, 4096);

        assertThat(out.json()).doesNotContain("\u0000").doesNotContain("\\n");
        assertThat(out.json()).doesNotContain("cameraResolution");
        assertThat(out.json().length()).isLessThan(4096);
    }

    @Test
    void device_RejectsOversizedDocument() {
        ObjectNode raw = obj();
        raw.put("userAgent", "u".repeat(300));
        raw.put("label", "l".repeat(120));
        raw.put("os", "o".repeat(80));
        raw.put("browser", "b".repeat(80));
        raw.put("platform", "p".repeat(80));
        raw.put("cameraLabel", "c".repeat(120));
        raw.put("timezone", "t".repeat(80));
        raw.put("language", "x".repeat(40));
        raw.put("screen", "s".repeat(40));

        // The sanitised document is well under 4096; an artificially tiny cap proves
        // the hard ceiling is enforced.
        assertThatThrownBy(() -> sanitizer.device(raw, 100))
                .isInstanceOf(AuthorTrialInputSanitizer.TrialRequestInvalidException.class)
                .extracting(e -> ((AuthorTrialInputSanitizer.TrialRequestInvalidException) e).code())
                .isEqualTo("device_too_large");
    }

    @Test
    void environment_ValidatesTimeBrightnessAndFrameRate() {
        ObjectNode raw = obj();
        raw.put("localTimeOfDay", "21:14");
        raw.put("brightness", 0.4212345);
        raw.put("exposureScore", 0.03);
        raw.put("frameRate", 29.97);
        raw.put("brightness2", 0.9);
        raw.put("timezone", "Europe/Istanbul");

        AuthorTrialInputSanitizer.SanitizedJson out = sanitizer.environment(raw, 2048);

        assertThat(out.json()).contains("\"localTimeOfDay\":\"21:14\"");
        assertThat(out.json()).contains("\"brightness\":0.4212");
        assertThat(out.json()).contains("\"frameRate\":29.97");
        assertThat(out.json()).doesNotContain("brightness2");
        assertThat(out.json()).doesNotContain("timezone");
    }

    @Test
    void environment_DropsOutOfRangeAndMalformedValues() {
        ObjectNode raw = obj();
        raw.put("localTimeOfDay", "25:99");
        raw.put("brightness", 3.0);
        raw.put("exposureScore", -1);
        raw.put("frameRate", 1000);

        AuthorTrialInputSanitizer.SanitizedJson out = sanitizer.environment(raw, 2048);

        assertThat(out.json()).isEqualTo("{}");
    }

    @Test
    void instrumentAndPreset_AreCappedAndNormalised() {
        assertThat(sanitizer.instrument("  DeepFaceLive 2.0  ")).isEqualTo("DeepFaceLive 2.0");
        assertThat(sanitizer.instrument("x".repeat(300))).hasSize(120);
        assertThat(sanitizer.instrument("   ")).isNull();

        assertThat(sanitizer.preset("Live_Face_Swap")).isEqualTo("live_face_swap");
        assertThat(sanitizer.preset("unknown-tool")).isEqualTo("other");
        assertThat(sanitizer.preset(null)).isNull();
    }

    @Test
    void versionAndReason_AreCapped() {
        assertThat(sanitizer.version("v".repeat(200))).hasSize(80);
        assertThat(sanitizer.reason("r".repeat(200))).hasSize(120);
        assertThat(sanitizer.reason(" \u0007 ")).isNull();
    }
}