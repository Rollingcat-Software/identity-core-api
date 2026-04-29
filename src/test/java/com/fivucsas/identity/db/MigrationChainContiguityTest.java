package com.fivucsas.identity.db;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AUDIT_2026-04-28_EDGE.md finding #8: with Flyway's
 * {@code out-of-order=false} default in prod, a hole in the migration
 * chain (V42 → V44 with no V43) means a future PR submitting a real V43
 * fails at boot ("Detected resolved migration not applied to database").
 *
 * <p>This test pins the V42…V48 window — the exact stretch flagged by the
 * audit — so the V43 reservation never silently disappears, and asserts
 * the global chain stays contiguous from V14 forward (V13 is a known
 * historical gap that pre-dates this audit and prod has already booted
 * past it; we don't try to back-fill).</p>
 */
@DisplayName("Flyway Migration Chain Contiguity Test")
class MigrationChainContiguityTest {

    private static final Pattern VERSION = Pattern.compile("^V(\\d+)__.+\\.sql$");

    /**
     * V13 is a known historical gap that pre-dates audit 2026-04-28 and
     * has been live in prod for many months. Ignored by the contiguity
     * check; documented here so future readers know it's not a bug.
     */
    private static final int CONTIGUITY_FLOOR = 14;

    @Test
    @DisplayName("V43 reservation is present (closes EDGE-P1 #8)")
    void v43Reservation_ShouldExist() throws IOException {
        Path v43 = Paths.get("src/main/resources/db/migration/V43__noop_reserved_v43_ships_as_V48.sql");
        assertThat(v43)
                .as("V43 was reserved as a no-op to close the V42→V44 gap. Do not delete or repurpose this slot.")
                .exists();
    }

    @Test
    @DisplayName("Migration chain has no gaps from V14 onwards")
    void migrationChain_ShouldBeContiguousFromV14() throws IOException {
        Path migrationsDir = Paths.get("src/main/resources/db/migration");
        assertThat(migrationsDir).exists();

        List<Integer> versions;
        try (Stream<Path> stream = Files.list(migrationsDir)) {
            versions = stream
                    .map(p -> p.getFileName().toString())
                    .map(VERSION::matcher)
                    .filter(Matcher::matches)
                    .map(m -> Integer.parseInt(m.group(1)))
                    .filter(v -> v >= CONTIGUITY_FLOOR)
                    .sorted()
                    .toList();
        }

        assertThat(versions).isNotEmpty();
        int max = versions.get(versions.size() - 1);
        for (int expected = CONTIGUITY_FLOOR; expected <= max; expected++) {
            int e = expected;
            assertThat(versions)
                    .as("Migration V%d__*.sql is missing — Flyway with out-of-order=false will fail at boot if a real V%d ships later. Reserve the slot with a no-op file (see V43 for the pattern).", e, e)
                    .contains(e);
        }
    }
}
