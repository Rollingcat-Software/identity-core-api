package com.fivucsas.identity.domain.model.auth;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The challenge vocabulary a PUZZLE step may list in
 * {@code puzzleConfig.allowedChallengeTypes}: the wire values of the
 * biometric service's {@code ChallengeType} enum
 * ({@code biometric-processor app/api/schemas/active_liveness.py}).
 *
 * <p>Identity forwards the allow-list to bio verbatim on puzzle-session create,
 * and bio rejects any value outside this set (HTTP 422), which makes every login
 * through that step fail closed. This enum is identity's single definition of
 * the set; the flow write path validates against it so a flow that can never
 * start a puzzle is refused at save time (HTTP 400) instead.
 *
 * <p>Keep it in lockstep with bio: adding a challenge there needs a matching
 * constant here before a flow may offer it.
 */
public enum PuzzleChallengeType {
    // face
    BLINK("blink"),
    SMILE("smile"),
    LIGHT("light"),
    TURN_LEFT("turn_left"),
    TURN_RIGHT("turn_right"),
    OPEN_MOUTH("open_mouth"),
    RAISE_EYEBROWS("raise_eyebrows"),
    CLOSE_LEFT_EYE("close_left_eye"),
    CLOSE_RIGHT_EYE("close_right_eye"),
    LOOK_UP("look_up"),
    LOOK_DOWN("look_down"),
    RAISE_LEFT_BROW("raise_left_brow"),
    RAISE_RIGHT_BROW("raise_right_brow"),
    NOD("nod"),
    SHAKE_HEAD("shake_head"),
    // hand
    FINGER_COUNT("finger_count"),
    SHAPE_TRACE("shape_trace"),
    WAVE("wave"),
    HAND_FLIP("hand_flip"),
    FINGER_TAP("finger_tap"),
    PINCH("pinch"),
    PEEK_A_BOO("peek_a_boo"),
    MATH("math"),
    HOLD_POSITION("hold_position");

    private static final Map<String, PuzzleChallengeType> BY_WIRE = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(PuzzleChallengeType::wireValue, Function.identity()));

    private final String wireValue;

    PuzzleChallengeType(String wireValue) {
        this.wireValue = wireValue;
    }

    /** The value bio accepts in {@code allowed_challenge_types}. */
    public String wireValue() {
        return wireValue;
    }

    /** The type for a wire value (trimmed, case-insensitive); empty when bio would reject it. */
    public static Optional<PuzzleChallengeType> fromWire(String value) {
        if (value == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(BY_WIRE.get(value.trim().toLowerCase(Locale.ROOT)));
    }

    public static boolean isKnown(String value) {
        return fromWire(value).isPresent();
    }
}
