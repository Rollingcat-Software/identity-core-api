package com.fivucsas.identity.application.service.devbench;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Boundary validation for one public device benchmark run.
 *
 * <p>The body comes from an anonymous browser, so it is treated as hostile: it must be a
 * JSON object no larger than {@link #MAX_BODY_BYTES}; only the top-level keys of the
 * published run document survive; the account id ({@code uid}) is always dropped; free
 * text that a person can type (the optional participant name) is capped and stripped of
 * control characters.
 */
public final class DevbenchRunSanitizer {

    /** A full run with 30 raw warm timings and long UA strings is about 4 KiB. */
    public static final int MAX_BODY_BYTES = 32 * 1024;

    static final int MAX_PARTICIPANT_CHARS = 60;
    static final int MAX_LABEL_CHARS = 120;
    static final int MAX_TOOL_CHARS = 80;
    static final int MAX_RUN_INDEX = 10;
    static final String TOOL_PREFIX = "fivucsas devbench";

    private static final Pattern BATCH_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");

    /** Top-level keys of the run document (artifact v3 and the app page share them). */
    static final Set<String> ALLOWED_KEYS = Set.of(
            "tool", "timestamp", "source", "submittedVia", "batchId", "runIndex", "runsInBatch",
            "participant", "deviceLabel", "deviceKey", "deviceType", "deviceAgeBand", "priceClass",
            "chargingReported", "chargingSource", "userAgent", "uaPlatform", "uaMobile", "uaHighEntropy",
            "browser", "webgl", "hardwareConcurrency", "deviceMemoryGB", "screen",
            "connectionEffectiveType", "timezone", "language", "crossOriginIsolated",
            "ortVersion", "ortBundle", "executionProvider", "wasmThreads",
            "model", "timingsMs", "errors", "battery", "visibilityAtEnd", "visibilityChanges");

    /** A run that passed validation. {@code payloadJson} is the cleaned document. */
    public record ValidRun(String tool, String batchId, int runIndex, String deviceKey, String payloadJson) {}

    public sealed interface Outcome permits Valid, Invalid {}

    public record Valid(ValidRun run) implements Outcome {}

    public record Invalid(String reason) implements Outcome {}

    private final ObjectMapper mapper;

    public DevbenchRunSanitizer(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public Outcome sanitize(byte[] body) {
        if (body == null || body.length == 0) {
            return new Invalid("empty_body");
        }
        if (body.length > MAX_BODY_BYTES) {
            return new Invalid("body_too_large");
        }
        JsonNode root;
        try {
            root = mapper.readTree(body);
        } catch (IOException e) {
            return new Invalid("malformed_json");
        }
        if (root == null || !root.isObject()) {
            return new Invalid("not_an_object");
        }
        ObjectNode doc = (ObjectNode) root;
        doc.retain(ALLOWED_KEYS);

        String tool = text(doc, "tool");
        if (tool == null || !tool.startsWith(TOOL_PREFIX) || tool.length() > MAX_TOOL_CHARS) {
            return new Invalid("unknown_tool");
        }
        String batchId = text(doc, "batchId");
        if (batchId == null || !BATCH_ID.matcher(batchId).matches()) {
            return new Invalid("bad_batch_id");
        }
        JsonNode runIndexNode = doc.get("runIndex");
        if (runIndexNode == null || !runIndexNode.canConvertToInt() || !runIndexNode.isIntegralNumber()
                || runIndexNode.intValue() < 1 || runIndexNode.intValue() > MAX_RUN_INDEX) {
            return new Invalid("bad_run_index");
        }
        JsonNode timings = doc.get("timingsMs");
        if (timings == null || !timings.isObject()) {
            return new Invalid("missing_timings");
        }

        cleanText(doc, "participant", MAX_PARTICIPANT_CHARS);
        cleanText(doc, "deviceLabel", MAX_LABEL_CHARS);
        cleanText(doc, "deviceKey", MAX_LABEL_CHARS);

        try {
            return new Valid(new ValidRun(tool, batchId, runIndexNode.intValue(),
                    text(doc, "deviceKey"), mapper.writeValueAsString(doc)));
        } catch (JsonProcessingException e) {
            return new Invalid("malformed_json");
        }
    }

    private static String text(ObjectNode doc, String key) {
        JsonNode node = doc.get(key);
        return node != null && node.isTextual() ? node.textValue() : null;
    }

    /** Keeps a string field only as a trimmed, control-free, length-capped string; anything else becomes null. */
    private static void cleanText(ObjectNode doc, String key, int maxChars) {
        if (!doc.has(key)) {
            return;
        }
        String value = text(doc, key);
        if (value == null) {
            doc.putNull(key);
            return;
        }
        String cleaned = CONTROL_CHARS.matcher(value).replaceAll("").trim();
        if (cleaned.length() > maxChars) {
            cleaned = cleaned.substring(0, maxChars).trim();
        }
        if (cleaned.isEmpty()) {
            doc.putNull(key);
        } else {
            doc.put(key, cleaned);
        }
    }
}
