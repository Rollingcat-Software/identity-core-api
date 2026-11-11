package com.fivucsas.identity.application.service.devbench;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Flattens run documents into the CSV the earlier artifact admin view produced, so
 * older and newer exports line up column by column ({@code id} and {@code receivedAt}
 * are added in front).
 */
public final class DevbenchCsv {

    /** One column definition: name and how to read it from a run document. */
    private record Column(String name, Function<JsonNode, String> reader) {}

    private static final List<Column> COLUMNS = List.of(
            col("timestamp", r -> txt(r, "timestamp")),
            col("source", r -> txt(r, "source")),
            col("batchId", r -> txt(r, "batchId")),
            col("runIndex", r -> txt(r, "runIndex")),
            col("participant", r -> txt(r, "participant")),
            col("deviceLabel", r -> txt(r, "deviceLabel")),
            col("deviceKey", r -> txt(r, "deviceKey")),
            col("deviceType", r -> txt(r, "deviceType")),
            col("chargingReported", r -> txt(r, "chargingReported")),
            col("uaPlatform", r -> txt(r, "uaPlatform")),
            col("uaMobile", r -> txt(r, "uaMobile")),
            col("uaModel", r -> txt(r.path("uaHighEntropy"), "model")),
            col("browser", r -> join(txt(r.path("browser"), "name"), txt(r.path("browser"), "version"))),
            col("hardwareConcurrency", r -> txt(r, "hardwareConcurrency")),
            col("deviceMemoryGB", r -> txt(r, "deviceMemoryGB")),
            col("screen", DevbenchCsv::screen),
            col("webglRenderer", r -> txt(r.path("webgl"), "renderer")),
            col("batteryStart", r -> txt(r.path("battery"), "levelStart")),
            col("batteryEnd", r -> txt(r.path("battery"), "levelEnd")),
            col("connection", r -> txt(r, "connectionEffectiveType")),
            col("timezone", r -> txt(r, "timezone")),
            col("language", r -> txt(r, "language")),
            col("visibilityAtEnd", r -> txt(r, "visibilityAtEnd")),
            col("visibilityChanges", r -> txt(r, "visibilityChanges")),
            col("crossOriginIsolated", r -> txt(r, "crossOriginIsolated")),
            col("ortVersion", r -> txt(r, "ortVersion")),
            col("modelFetchMs", r -> firstOf(txt(r.path("timingsMs"), "modelFetch_appHost"),
                    txt(r.path("timingsMs"), "modelFetch_artifactHost"))),
            col("sessionCreateCold", r -> txt(r.path("timingsMs"), "sessionCreateCold")),
            col("firstInference", r -> txt(r.path("timingsMs"), "firstInference")),
            col("p50", r -> txt(r.path("timingsMs").path("warm"), "p50")),
            col("p95", r -> txt(r.path("timingsMs").path("warm"), "p95")),
            col("mean", r -> txt(r.path("timingsMs").path("warm"), "mean")),
            col("min", r -> txt(r.path("timingsMs").path("warm"), "min")),
            col("max", r -> txt(r.path("timingsMs").path("warm"), "max")),
            col("sha256Match", r -> txt(r.path("model"), "sha256Match")),
            col("errors", DevbenchCsv::errors),
            col("tool", r -> txt(r, "tool")));

    private DevbenchCsv() {
    }

    /** {@code rows} maps each run id and arrival time to its parsed document. */
    public static String render(List<Row> rows) {
        StringBuilder out = new StringBuilder();
        out.append("id,receivedAt,")
                .append(COLUMNS.stream().map(Column::name).collect(Collectors.joining(",")))
                .append('\n');
        for (Row row : rows) {
            Map<String, String> cells = new LinkedHashMap<>();
            cells.put("id", row.id());
            cells.put("receivedAt", row.receivedAt());
            for (Column c : COLUMNS) {
                cells.put(c.name(), c.reader().apply(row.doc()));
            }
            out.append(cells.values().stream().map(DevbenchCsv::cell).collect(Collectors.joining(",")))
                    .append('\n');
        }
        return out.toString();
    }

    public record Row(String id, String receivedAt, JsonNode doc) {}

    /**
     * RFC 4180 quoting, plus a leading apostrophe for cells a spreadsheet would run as a
     * formula (CSV injection: participant names and UA strings come from anonymous visitors).
     */
    static String cell(String value) {
        if (value == null) {
            return "";
        }
        String v = value;
        if (!v.isEmpty() && "=+-@\t\r".indexOf(v.charAt(0)) >= 0 && !isNumber(v)) {
            v = "'" + v;
        }
        if (v.indexOf(',') >= 0 || v.indexOf('"') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0) {
            return '"' + v.replace("\"", "\"\"") + '"';
        }
        return v;
    }

    private static boolean isNumber(String v) {
        try {
            Double.parseDouble(v);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static Column col(String name, Function<JsonNode, String> reader) {
        return new Column(name, reader);
    }

    private static String txt(JsonNode node, String key) {
        JsonNode v = node == null ? null : node.get(key);
        return v == null || v.isNull() || v.isMissingNode() || v.isContainerNode() ? null : v.asText();
    }

    private static String join(String a, String b) {
        if (a == null) {
            return null;
        }
        return b == null ? a : a + " " + b;
    }

    private static String firstOf(String a, String b) {
        return a != null ? a : b;
    }

    private static String screen(JsonNode r) {
        JsonNode s = r.path("screen");
        String w = txt(s, "width");
        return w == null ? null : w + "x" + txt(s, "height") + "@" + txt(s, "dpr");
    }

    private static String errors(JsonNode r) {
        JsonNode e = r.path("errors");
        if (!e.isArray() || e.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        e.forEach(x -> sb.append(sb.isEmpty() ? "" : "; ").append(x.asText()));
        return sb.toString();
    }
}
