package com.fivucsas.identity.application.service.authorTrial;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Boundary validation for the public trial surface. The body comes from a
 * browser with no login, so it is hostile: only allow-listed scalar keys
 * survive, strings are stripped of control characters and length-capped,
 * numbers are bounded, and the resulting JSON has a hard size cap.
 *
 * <p>The device/environment data is research metadata. It is never used for an
 * authentication decision and never contains an image, a frame or a template.
 */
public final class AuthorTrialInputSanitizer {

    public static final int MAX_INSTRUMENT_CHARS = 120;
    public static final int MAX_VERSION_CHARS = 80;
    public static final int MAX_REASON_CHARS = 120;

    static final Set<String> INSTRUMENT_PRESETS = Set.of(
            "live_face_swap", "deepfake_replay", "virtual_camera", "other");

    private static final Set<String> DEVICE_KEYS = Set.of(
            "label", "type", "os", "platform", "browser", "browserVersion", "screen",
            "cameraLabel", "cameraResolution", "hardwareConcurrency", "deviceMemoryGB",
            "userAgent", "language", "timezone");

    private static final Set<String> ENV_KEYS = Set.of(
            "localTimeOfDay", "brightness", "exposureScore", "frameRate");

    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");
    private static final Pattern TIME_OF_DAY = Pattern.compile("([01]\\d|2[0-3]):[0-5]\\d");
    private static final Pattern RESOLUTION = Pattern.compile("\\d{2,5}x\\d{2,5}");

    private final ObjectMapper mapper;

    public AuthorTrialInputSanitizer(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** A sanitised JSON document plus its byte length. */
    public record SanitizedJson(String json, int bytes) {}

    /**
     * Sanitises the device object. Unknown keys are dropped. Returns an empty
     * document (never null) when the input is absent or not an object.
     *
     * @throws TrialRequestInvalidException when the result exceeds the cap
     */
    public SanitizedJson device(JsonNode raw, int maxBytes) {
        ObjectNode out = mapper.createObjectNode();
        if (raw != null && raw.isObject()) {
            text(out, raw, "label", 120);
            text(out, raw, "type", 24);
            text(out, raw, "os", 80);
            text(out, raw, "platform", 80);
            text(out, raw, "browser", 80);
            text(out, raw, "browserVersion", 40);
            text(out, raw, "screen", 40);
            text(out, raw, "cameraLabel", 120);
            resolution(out, raw);
            number(out, raw, "hardwareConcurrency", 1, 1_024);
            number(out, raw, "deviceMemoryGB", 0, 1_024);
            text(out, raw, "userAgent", 300);
            text(out, raw, "language", 40);
            text(out, raw, "timezone", 80);
        }
        return finish(out, maxBytes, "device_too_large", DEVICE_KEYS);
    }

    /** Sanitises the per-attempt environment object. */
    public SanitizedJson environment(JsonNode raw, int maxBytes) {
        ObjectNode out = mapper.createObjectNode();
        if (raw != null && raw.isObject()) {
            JsonNode time = raw.get("localTimeOfDay");
            if (time != null && time.isTextual()
                    && TIME_OF_DAY.matcher(time.textValue().trim()).matches()) {
                out.put("localTimeOfDay", time.textValue().trim());
            }
            unit(out, raw, "brightness");
            unit(out, raw, "exposureScore");
            JsonNode fps = raw.get("frameRate");
            if (fps != null && fps.isNumber()) {
                double v = fps.doubleValue();
                if (Double.isFinite(v) && v >= 0 && v <= 240) {
                    out.put("frameRate", round(v));
                }
            }
        }
        return finish(out, maxBytes, "env_too_large", ENV_KEYS);
    }

    public String instrument(String raw) {
        return clean(raw, MAX_INSTRUMENT_CHARS);
    }

    public String preset(String raw) {
        String value = clean(raw, 40);
        if (value == null) {
            return null;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        return INSTRUMENT_PRESETS.contains(normalized) ? normalized : "other";
    }

    public String version(String raw) {
        return clean(raw, MAX_VERSION_CHARS);
    }

    public String reason(String raw) {
        return clean(raw, MAX_REASON_CHARS);
    }

    private SanitizedJson finish(ObjectNode out, int maxBytes, String tooLargeCode, Set<String> allowed) {
        out.retain(allowed);
        try {
            String json = mapper.writeValueAsString(out);
            int bytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            if (bytes > maxBytes) {
                throw new TrialRequestInvalidException(tooLargeCode);
            }
            return new SanitizedJson(json, bytes);
        } catch (JsonProcessingException e) {
            throw new TrialRequestInvalidException("malformed_json");
        }
    }

    private static void text(ObjectNode out, JsonNode raw, String key, int max) {
        JsonNode node = raw.get(key);
        if (node == null || !node.isTextual()) {
            return;
        }
        String value = clean(node.textValue(), max);
        if (value != null) {
            out.put(key, value);
        }
    }

    private static void resolution(ObjectNode out, JsonNode raw) {
        JsonNode node = raw.get("cameraResolution");
        if (node == null || !node.isTextual()) {
            return;
        }
        String value = node.textValue().trim();
        if (RESOLUTION.matcher(value).matches()) {
            out.put("cameraResolution", value);
        }
    }

    private static void number(ObjectNode out, JsonNode raw, String key, double min, double max) {
        JsonNode node = raw.get(key);
        if (node == null || !node.isNumber()) {
            return;
        }
        double value = node.doubleValue();
        if (Double.isFinite(value) && value >= min && value <= max) {
            out.put(key, round(value));
        }
    }

    private static void unit(ObjectNode out, JsonNode raw, String key) {
        JsonNode node = raw.get(key);
        if (node == null || !node.isNumber()) {
            return;
        }
        double value = node.doubleValue();
        if (Double.isFinite(value) && value >= 0 && value <= 1) {
            out.put(key, round(value));
        }
    }

    private static double round(double value) {
        return Math.round(value * 10_000d) / 10_000d;
    }

    private static String clean(String raw, int max) {
        if (raw == null) {
            return null;
        }
        String cleaned = CONTROL_CHARS.matcher(raw).replaceAll("").trim();
        if (cleaned.isEmpty()) {
            return null;
        }
        return cleaned.length() <= max ? cleaned : cleaned.substring(0, max).trim();
    }

    /** Checked failure with a stable client code. */
    public static final class TrialRequestInvalidException extends RuntimeException {
        private final String code;

        public TrialRequestInvalidException(String code) {
            super(code);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    /** Visible for tests: the allow-list of accepted presets. */
    public static Set<String> instrumentPresets() {
        return Set.copyOf(INSTRUMENT_PRESETS);
    }
}