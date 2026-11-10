package com.fivucsas.identity.application.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The one definition of a PUZZLE step's persisted configuration.
 *
 * <p>The {@code auth_flow_steps.config} JSONB blob of a PUZZLE step has exactly
 * one accepted shape:
 * <pre>{"puzzleConfig":{"allowedChallengeTypes":[...],"count":N,
 *                   "difficulty":"...","alsoMatchFaceIdentity":true|false}}</pre>
 * The same blob is surfaced unchanged to clients as {@code stepConfig} by the
 * login-config endpoint. Every reader (session create, the PUZZLE step
 * handler) and the flow write path go through {@link #parse(String)}, so the
 * writer and the readers cannot drift apart again (they did: the flow builder
 * wrote the inner object without the {@code puzzleConfig} key, and every
 * reader failed closed).
 *
 * @param allowedChallengeTypes lower-cased challenge ids; may be empty, see
 *                              {@link #hasChallenges()}
 * @param count                 requested challenges, at least 1 (not clamped to
 *                              the allow-list here; the session-create path clamps)
 * @param difficulty            optional hint passed through to bio, may be null
 * @param alsoMatchFaceIdentity identity binding requested by the tenant
 */
public record PuzzleStepConfig(List<String> allowedChallengeTypes,
                               int count,
                               String difficulty,
                               boolean alsoMatchFaceIdentity) {

    /** The key that wraps the PUZZLE settings inside the step config blob. */
    public static final String KEY = "puzzleConfig";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public PuzzleStepConfig {
        allowedChallengeTypes = List.copyOf(allowedChallengeTypes);
    }

    /**
     * Parses a step config blob. Empty when the blob is null, blank, not JSON or
     * lacks the {@code puzzleConfig} object. A present object with no usable
     * allow-list still parses (so its binding flag is honoured); callers that
     * need challenges check {@link #hasChallenges()}.
     */
    public static Optional<PuzzleStepConfig> parse(String configJson) {
        if (configJson == null || configJson.isBlank()) {
            return Optional.empty();
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(configJson);
        } catch (Exception e) {
            return Optional.empty();
        }
        JsonNode puzzle = root == null ? null : root.get(KEY);
        if (puzzle == null || !puzzle.isObject()) {
            return Optional.empty();
        }
        List<String> allowed = new ArrayList<>();
        JsonNode typesNode = puzzle.get("allowedChallengeTypes");
        if (typesNode != null && typesNode.isArray()) {
            for (JsonNode t : typesNode) {
                String v = t.isTextual() ? t.asText() : null;
                if (v != null && !v.isBlank()) {
                    allowed.add(v.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        JsonNode countNode = puzzle.get("count");
        int count = (countNode != null && countNode.isInt()) ? Math.max(1, countNode.asInt()) : 1;
        JsonNode diffNode = puzzle.get("difficulty");
        String difficulty = (diffNode != null && diffNode.isTextual()) ? diffNode.asText() : null;
        JsonNode bindNode = puzzle.get("alsoMatchFaceIdentity");
        boolean alsoMatch = bindNode != null && bindNode.asBoolean(false);
        return Optional.of(new PuzzleStepConfig(allowed, count, difficulty, alsoMatch));
    }

    /** True when at least one challenge type is allowed (a session can be issued). */
    public boolean hasChallenges() {
        return !allowedChallengeTypes.isEmpty();
    }
}
