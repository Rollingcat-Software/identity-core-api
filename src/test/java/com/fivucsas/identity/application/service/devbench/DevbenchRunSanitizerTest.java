package com.fivucsas.identity.application.service.devbench;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class DevbenchRunSanitizerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final DevbenchRunSanitizer sanitizer = new DevbenchRunSanitizer(mapper);

    static String run(String extra) {
        return "{\"tool\":\"fivucsas devbench app v1\",\"batchId\":\"20261110abcd\",\"runIndex\":2,"
                + "\"deviceKey\":\"sm-a145f\",\"timingsMs\":{\"sessionCreateCold\":812.4,\"warm\":{\"p50\":95.1}}"
                + extra + "}";
    }

    private DevbenchRunSanitizer.Outcome sanitize(String json) {
        return sanitizer.sanitize(json.getBytes(StandardCharsets.UTF_8));
    }

    private String reason(String json) {
        return ((DevbenchRunSanitizer.Invalid) sanitize(json)).reason();
    }

    private JsonNode payload(String json) throws Exception {
        return mapper.readTree(((DevbenchRunSanitizer.Valid) sanitize(json)).run().payloadJson());
    }

    @Test
    void sanitize_WhenValidRun_ShouldKeepFieldsAndExtractColumns() throws Exception {
        DevbenchRunSanitizer.Outcome out = sanitize(run(",\"hardwareConcurrency\":8"));

        assertThat(out).isInstanceOf(DevbenchRunSanitizer.Valid.class);
        DevbenchRunSanitizer.ValidRun v = ((DevbenchRunSanitizer.Valid) out).run();
        assertThat(v.batchId()).isEqualTo("20261110abcd");
        assertThat(v.runIndex()).isEqualTo(2);
        assertThat(v.deviceKey()).isEqualTo("sm-a145f");
        JsonNode p = mapper.readTree(v.payloadJson());
        assertThat(p.path("timingsMs").path("warm").path("p50").asDouble()).isEqualTo(95.1);
        assertThat(p.path("hardwareConcurrency").asInt()).isEqualTo(8);
    }

    @Test
    void sanitize_WhenUnknownOrAccountKeys_ShouldDropThem() throws Exception {
        JsonNode p = payload(run(",\"uid\":\"user-123\",\"ip\":\"1.2.3.4\",\"gps\":{\"lat\":41}"));

        assertThat(p.has("uid")).isFalse();
        assertThat(p.has("ip")).isFalse();
        assertThat(p.has("gps")).isFalse();
    }

    @Test
    void sanitize_WhenParticipantHasControlCharsAndIsLong_ShouldCleanAndCap() throws Exception {
        String longName = "A".repeat(200);
        JsonNode p = payload(run(",\"participant\":\"  Ay\\u0000\\u0007" + longName + "  \""));

        String name = p.path("participant").asText();
        assertThat(name).startsWith("AyA").doesNotContain("\u0000").doesNotContain("\u0007");
        assertThat(name).hasSize(DevbenchRunSanitizer.MAX_PARTICIPANT_CHARS);
    }

    @Test
    void sanitize_WhenParticipantBlankOrNotText_ShouldBecomeNull() throws Exception {
        assertThat(payload(run(",\"participant\":\"   \"")).path("participant").isNull()).isTrue();
        assertThat(payload(run(",\"participant\":{\"a\":1}")).path("participant").isNull()).isTrue();
    }

    @Test
    void sanitize_WhenBodyTooLarge_ShouldReject() {
        String big = run(",\"errors\":[\"" + "x".repeat(DevbenchRunSanitizer.MAX_BODY_BYTES) + "\"]");
        assertThat(reason(big)).isEqualTo("body_too_large");
    }

    @Test
    void sanitize_WhenNotJsonObject_ShouldReject() {
        assertThat(reason("not json")).isEqualTo("malformed_json");
        assertThat(reason("[1,2]")).isEqualTo("not_an_object");
        assertThat(sanitizer.sanitize(new byte[0])).isInstanceOf(DevbenchRunSanitizer.Invalid.class);
    }

    @Test
    void sanitize_WhenToolIsForeign_ShouldReject() {
        String json = run("").replace("fivucsas devbench app v1", "spam");
        assertThat(reason(json)).isEqualTo("unknown_tool");
    }

    @Test
    void sanitize_WhenBatchIdHasMarkup_ShouldReject() {
        String json = run("").replace("20261110abcd", "<script>");
        assertThat(reason(json)).isEqualTo("bad_batch_id");
    }

    @Test
    void sanitize_WhenRunIndexOutOfRangeOrFractional_ShouldReject() {
        assertThat(reason(run("").replace("\"runIndex\":2", "\"runIndex\":0"))).isEqualTo("bad_run_index");
        assertThat(reason(run("").replace("\"runIndex\":2", "\"runIndex\":99"))).isEqualTo("bad_run_index");
        assertThat(reason(run("").replace("\"runIndex\":2", "\"runIndex\":1.5"))).isEqualTo("bad_run_index");
    }

    @Test
    void sanitize_WhenTimingsMissing_ShouldReject() {
        String json = "{\"tool\":\"fivucsas devbench app v1\",\"batchId\":\"b1\",\"runIndex\":1}";
        assertThat(reason(json)).isEqualTo("missing_timings");
    }
}
