package com.fivucsas.identity.application.service.authorTrial;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Attempt;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The trial export in the OLD {@code sessions.csv} column order, followed by the
 * documented extension columns (docs/AUTHOR_TRIAL_CONTRACT.md §3.7).
 *
 * <p>The first 23 columns are the Paper B pilot schema, so the legacy analyzer
 * can still read a trial export; the extension columns carry the trial-specific
 * plan slot, instrument, score and environment data. Rows with a technical
 * outcome are marked {@code excluded=yes}; the analysis must skip them before
 * validating the rest.
 */
public final class AuthorTrialCsv {

    public static final String HEADER = String.join(",",
            // Legacy sessions.csv schema, original order.
            "date", "participant", "operator", "session_no", "condition", "attack_type",
            "attack_medium", "binding", "k", "difficulty", "contract",
            "face_embedding_liveness_mode", "deployment_commits", "outcome",
            "liveness_verdict", "identity_verdict", "failure_reason", "completion_time_s",
            "device_browser", "lighting", "server_session_id", "excluded", "notes",
            // Trial extension.
            "mode", "target", "instrument", "instrument_preset", "round", "position",
            "challenge", "planned_challenge", "identity_score", "identity_distance",
            "identity_threshold", "latency_ms", "client_latency_ms", "started_at",
            "decided_at", "local_time_of_day", "brightness", "exposure_score",
            "frame_rate", "camera_label", "camera_resolution", "device_label", "os",
            "browser", "screen", "web_version", "api_version", "bio_version",
            "mfa_session_id", "step_outcome", "challenges_submitted",
            "last_challenge_verdict", "last_challenge_reason", "attempt_id");

    private AuthorTrialCsv() {
    }

    /** One attempt plus its participant-local session number. */
    public record Row(Attempt attempt, int sessionNo) {}

    public static String render(List<Row> rows, ObjectMapper mapper) {
        StringBuilder out = new StringBuilder(HEADER).append('\n');
        for (Row row : rows) {
            out.append(renderRow(row, mapper)).append('\n');
        }
        return out.toString();
    }

    static String renderRow(Row row, ObjectMapper mapper) {
        Attempt a = row.attempt();
        JsonNode device = parse(mapper, a.deviceJson());
        JsonNode env = parse(mapper, a.envJson());

        String outcome = a.outcome();
        // A reject with no liveness verdict is a client/technical close, not a
        // biometric decision (the page cannot mint a reject on its own); mark it
        // excluded so the analysis skips it instead of failing its schema check.
        boolean excluded = outcome == null || "error".equals(outcome) || "abandoned".equals(outcome)
                || ("reject".equals(outcome)
                && (a.livenessVerdict() == null || a.livenessVerdict().isBlank()));
        boolean attack = "attack".equals(a.mode());

        List<String> cells = new ArrayList<>(60);
        // Legacy columns.
        cells.add(a.startedAt() == null ? ""
                : LocalDate.ofInstant(a.startedAt(), ZoneOffset.UTC).toString());
        cells.add(a.targetCode());                                  // participant = victim
        cells.add(a.participantCode());                             // operator
        cells.add(String.valueOf(row.sessionNo()));
        cells.add(attack ? "attack" : "bona_fide");                 // condition
        cells.add(attack ? attackType(a) : "none");
        cells.add(attack ? a.instrument() : null);                  // attack_medium
        cells.add(a.binding() ? "on" : "off");
        cells.add(String.valueOf(a.challengeCount()));
        cells.add(a.difficulty());
        cells.add(a.traceContract());
        cells.add(a.livenessMode());
        cells.add(deployment(a));
        cells.add(outcome);
        cells.add(a.livenessVerdict());
        cells.add(a.identityVerdict());
        cells.add(a.failureReason());
        cells.add(completionSeconds(a));
        cells.add(deviceBrowser(device));
        cells.add(lighting(env));
        cells.add(a.puzzleSessionId());
        cells.add(excluded ? "yes" : "");
        cells.add(notes(a, excluded));
        // Trial extension.
        cells.add(a.mode());
        cells.add(a.targetCode());
        cells.add(a.instrument());
        cells.add(a.instrumentPreset());
        cells.add(String.valueOf(a.roundNo()));
        cells.add(String.valueOf(a.position()));
        cells.add(a.challenge());
        cells.add(a.plannedChallenge());
        cells.add(number(a.identityScore()));
        cells.add(number(a.identityDistance()));
        cells.add(number(a.identityThreshold()));
        cells.add(latencyMs(a));
        cells.add(a.clientLatencyMs() == null ? "" : String.valueOf(a.clientLatencyMs()));
        cells.add(a.startedAt() == null ? "" : a.startedAt().toString());
        cells.add(a.decidedAt() == null ? "" : a.decidedAt().toString());
        cells.add(text(env, "localTimeOfDay"));
        cells.add(text(env, "brightness"));
        cells.add(text(env, "exposureScore"));
        cells.add(text(env, "frameRate"));
        cells.add(text(device, "cameraLabel"));
        cells.add(text(device, "cameraResolution"));
        cells.add(text(device, "label"));
        cells.add(text(device, "os"));
        cells.add(text(device, "browser"));
        cells.add(text(device, "screen"));
        cells.add(a.webVersion());
        cells.add(a.apiVersion());
        cells.add(a.bioVersion());
        cells.add(a.mfaSessionId() == null ? "" : a.mfaSessionId().toString());
        cells.add(a.stepOutcome());
        cells.add(String.valueOf(a.challengesSubmitted()));
        cells.add(a.lastChallengeVerdict());
        cells.add(a.lastChallengeReason());
        cells.add(a.id() == null ? "" : a.id().toString());

        StringBuilder line = new StringBuilder();
        for (int i = 0; i < cells.size(); i++) {
            if (i > 0) {
                line.append(',');
            }
            line.append(cell(cells.get(i)));
        }
        return line.toString();
    }

    private static String attackType(Attempt a) {
        String preset = a.instrumentPreset();
        if (preset == null || preset.isBlank()) {
            return "other";
        }
        return switch (preset) {
            case "live_face_swap", "deepfake_replay", "virtual_camera" -> preset;
            default -> "other";
        };
    }

    private static String deployment(Attempt a) {
        return "bio=" + fallback(a.bioVersion())
                + ";api=" + fallback(a.apiVersion())
                + ";web=" + fallback(a.webVersion());
    }

    private static String notes(Attempt a, boolean excluded) {
        List<String> parts = new ArrayList<>();
        if (a.instrumentPreset() != null) {
            parts.add(a.instrumentPreset());
        }
        if (excluded) {
            parts.add("excluded:" + (a.outcome() == null ? "not_decided" : a.outcome()));
        }
        return parts.isEmpty() ? "" : String.join("; ", parts);
    }

    private static String completionSeconds(Attempt a) {
        if (a.startedAt() == null || a.decidedAt() == null) {
            return "";
        }
        long ms = Math.max(0, a.decidedAt().toEpochMilli() - a.startedAt().toEpochMilli());
        return String.format(Locale.ROOT, "%.3f", ms / 1000.0);
    }

    private static String latencyMs(Attempt a) {
        if (a.startedAt() == null || a.decidedAt() == null) {
            return "";
        }
        return String.valueOf(Math.max(0, a.decidedAt().toEpochMilli() - a.startedAt().toEpochMilli()));
    }

    private static String deviceBrowser(JsonNode device) {
        List<String> parts = new ArrayList<>();
        addPart(parts, text(device, "label"));
        addPart(parts, text(device, "os"));
        addPart(parts, text(device, "browser"));
        addPart(parts, text(device, "cameraLabel"));
        return String.join(" / ", parts);
    }

    private static void addPart(List<String> parts, String value) {
        if (value != null && !value.isBlank()) {
            parts.add(value);
        }
    }

    private static String lighting(JsonNode env) {
        String raw = text(env, "brightness");
        if (raw == null || raw.isBlank()) {
            return "unknown";
        }
        try {
            double brightness = Double.parseDouble(raw);
            if (brightness >= 0.65) {
                return "bright";
            }
            if (brightness >= 0.40) {
                return "moderate";
            }
            if (brightness >= 0.20) {
                return "dim";
            }
            return "dark";
        } catch (NumberFormatException e) {
            return "unknown";
        }
    }

    private static String number(Double value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static String fallback(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
    }

    private static String text(JsonNode node, String key) {
        if (node == null || !node.isObject()) {
            return "";
        }
        JsonNode v = node.get(key);
        return v == null || v.isNull() ? "" : v.asText();
    }

    private static JsonNode parse(ObjectMapper mapper, String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            return null;
        }
    }

    /** RFC 4180 cell: quote when needed, double embedded quotes. */
    static String cell(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        boolean needsQuotes = raw.indexOf(',') >= 0 || raw.indexOf('"') >= 0
                || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0;
        if (!needsQuotes) {
            return raw;
        }
        return '"' + raw.replace("\"", "\"\"") + '"';
    }

    /** Visible for tests: stable ISO instant rendering. */
    static String iso(Instant instant) {
        return instant == null ? "" : instant.toString();
    }
}