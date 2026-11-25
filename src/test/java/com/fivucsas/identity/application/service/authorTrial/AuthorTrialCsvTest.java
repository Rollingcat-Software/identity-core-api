package com.fivucsas.identity.application.service.authorTrial;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Attempt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuthorTrialCsv — sessions.csv schema + documented extension")
class AuthorTrialCsvTest {

    private static final UUID ATTEMPT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID MFA_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final Instant START = Instant.parse("2026-11-24T18:14:05Z");

    private final ObjectMapper mapper = new ObjectMapper();

    private static Attempt attempt(String mode, String outcome, String deviceJson, String envJson) {
        return new Attempt(ATTEMPT_ID, UUID.randomUUID(), "P1", mode, "P2",
                "attack".equals(mode) ? "DeepFaceLive 2.0" : null,
                "attack".equals(mode) ? "deepfake_replay" : null,
                "blink", "blink", 2, 3, UUID.randomUUID(), true, "easy", 1, "audit",
                "v2", MFA_ID, "puzzle-session-1", START, START.plusSeconds(12), outcome,
                "pass", "attack".equals(mode) ? "fail" : "pass", "fail".equals(outcome) ? "fail" : "pass",
                "reject".equals(outcome) ? "identity_match_failed" : null,
                0.71, 0.29, 0.40, 1200, 1, "pass", null,
                deviceJson, envJson, "web-sha", "api-sha", "bio-1.2.3");
    }

    @Test
    void header_HasLegacyPrefixAndDocumentedExtension() {
        List<String> columns = List.of(AuthorTrialCsv.HEADER.split(",", -1));
        assertThat(columns).hasSize(57);
        assertThat(columns.subList(0, 6)).containsExactly(
                "date", "participant", "operator", "session_no", "condition", "attack_type");
        assertThat(columns).contains("excluded", "notes", "mode", "target", "instrument",
                "round", "position", "challenge", "identity_score", "latency_ms",
                "started_at", "brightness", "frame_rate", "attempt_id");
        assertThat(columns.get(columns.size() - 1)).isEqualTo("attempt_id");
    }

    @Test
    void genuineRow_MapsLegacyColumnsAndEnvironment() {
        String device = "{\"label\":\"HP Victus\",\"os\":\"Windows\",\"browser\":\"Chrome\","
                + "\"cameraLabel\":\"HD Webcam\",\"cameraResolution\":\"1280x720\","
                + "\"screen\":\"1920x1080@1\"}";
        String env = "{\"localTimeOfDay\":\"21:14\",\"brightness\":0.72,"
                + "\"exposureScore\":0.03,\"frameRate\":29.8}";

        String row = AuthorTrialCsv.renderRow(
                new AuthorTrialCsv.Row(attempt("genuine", "accept", device, env), 7), mapper);
        List<String> cells = List.of(row.split(",", -1));

        assertThat(cells.get(0)).isEqualTo("2026-11-24");          // date (UTC)
        assertThat(cells.get(1)).isEqualTo("P2");                  // participant = victim
        assertThat(cells.get(2)).isEqualTo("P1");                  // operator = author
        assertThat(cells.get(3)).isEqualTo("7");                   // session_no
        assertThat(cells.get(4)).isEqualTo("bona_fide");           // condition
        assertThat(cells.get(5)).isEqualTo("none");                // attack_type
        assertThat(cells.get(7)).isEqualTo("on");                  // binding
        assertThat(cells.get(8)).isEqualTo("1");                   // k
        assertThat(cells.get(10)).isEqualTo("v2");                 // contract
        assertThat(cells.get(13)).isEqualTo("accept");             // outcome
        assertThat(cells.get(17)).isEqualTo("12.000");             // completion_time_s
        assertThat(cells.get(18)).isEqualTo("HP Victus / Windows / Chrome / HD Webcam");
        assertThat(cells.get(19)).isEqualTo("bright");             // lighting bucket
        assertThat(cells.get(20)).isEqualTo("puzzle-session-1");
        assertThat(cells.get(21)).isEmpty();                       // not excluded
        assertThat(cells.get(23)).isEqualTo("genuine");            // mode
        assertThat(cells.get(24)).isEqualTo("P2");                 // target
        assertThat(cells.get(28)).isEqualTo("3");                  // position
        assertThat(cells.get(31)).isEqualTo("0.71");               // identity_score
        assertThat(cells.get(34)).isEqualTo("12000");              // latency_ms
        assertThat(cells.get(35)).isEqualTo("1200");               // client_latency_ms
        assertThat(cells.get(38)).isEqualTo("21:14");              // local_time_of_day
        assertThat(cells.get(39)).isEqualTo("0.72");               // brightness
        assertThat(cells.get(41)).isEqualTo("29.8");               // frame_rate
        assertThat(cells.get(42)).isEqualTo("HD Webcam");          // camera_label
        assertThat(cells.get(44)).isEqualTo("HP Victus");          // device_label
    }

    @Test
    void attackRow_MapsInstrumentAndExcludesTechnicalOutcomes() {
        String row = AuthorTrialCsv.renderRow(
                new AuthorTrialCsv.Row(attempt("attack", "error", null, null), 1), mapper);
        List<String> cells = List.of(row.split(",", -1));

        assertThat(cells.get(4)).isEqualTo("attack");
        assertThat(cells.get(5)).isEqualTo("deepfake_replay");
        assertThat(cells.get(6)).isEqualTo("DeepFaceLive 2.0");
        assertThat(cells.get(13)).isEqualTo("error");
        assertThat(cells.get(21)).isEqualTo("yes");
        assertThat(cells.get(23)).isEqualTo("attack");
        assertThat(cells.get(26)).isEqualTo("deepfake_replay");
        assertThat(cells.get(19)).isEqualTo("unknown");
    }

    @Test
    void rejectWithoutABiometricVerdict_IsExcluded() {
        Attempt base = attempt("genuine", "reject", null, null);
        Attempt clientOnly = new Attempt(base.id(), base.tenantId(), base.participantCode(),
                base.mode(), base.targetCode(), null, null, base.plannedChallenge(),
                base.challenge(), base.roundNo(), base.position(), null, true, "easy", 1,
                "audit", "v2", base.mfaSessionId(), null, base.startedAt(), base.decidedAt(),
                "reject", null, null, null, "server_did_not_authenticate", null, null,
                null, null, 0, null, null, null, null, null, null, null);

        String row = AuthorTrialCsv.renderRow(new AuthorTrialCsv.Row(clientOnly, 1), mapper);
        List<String> cells = List.of(row.split(",", -1));
        assertThat(cells.get(21)).isEqualTo("yes");
    }

    @Test
    void cells_AreRfc4180Escaped() {
        assertThat(AuthorTrialCsv.cell("plain")).isEqualTo("plain");
        assertThat(AuthorTrialCsv.cell("a,b")).isEqualTo("\"a,b\"");
        assertThat(AuthorTrialCsv.cell("a\"b")).isEqualTo("\"a\"\"b\"");
        assertThat(AuthorTrialCsv.cell("a\nb")).isEqualTo("\"a\nb\"");
        assertThat(AuthorTrialCsv.cell(null)).isEmpty();
    }

    @Test
    void render_ProducesHeaderPlusOneLinePerRow() {
        String csv = AuthorTrialCsv.render(List.of(
                new AuthorTrialCsv.Row(attempt("genuine", "accept", null, null), 1),
                new AuthorTrialCsv.Row(attempt("attack", "reject", null, null), 1)), mapper);
        String[] lines = csv.split("\n");
        assertThat(lines).hasSize(3);
        assertThat(lines[0]).isEqualTo(AuthorTrialCsv.HEADER);
    }
}