package com.fivucsas.identity.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Pre-merge smoke for the application-*.yml profile files.
 *
 * <p>SnakeYAML's default {@code LoaderOptions} silently accepts duplicate keys
 * — the second occurrence wins and the first is dropped. This exact failure
 * mode shipped to prod via api PR #62 (commit {@code 666b2c3}, 2026-05-02):
 * a duplicated {@code app:} root in {@code application-prod.yml} caused the
 * first block (cors / security overrides) to be silently discarded at
 * Spring Boot startup, which only surfaced as an emergency hotfix once an
 * end-user hit the misconfigured CORS rule.
 *
 * <p>This test parses each profile YAML with {@code allowDuplicateKeys=false}
 * so the regression is caught at unit-test time. Add a new test method when
 * a new {@code application-*.yml} file is added to {@code src/main/resources}.
 *
 * <p>References:
 * <ul>
 *   <li>{@code TEST_REVIEW_2026-05-01.md} (deferred items — YAML smoke)</li>
 *   <li>{@code feedback_pr_review_workflow.md}</li>
 * </ul>
 */
@DisplayName("application-*.yml profile YAML duplicate-key smoke")
class YamlProfileConfigTest {

    @Test
    @DisplayName("application.yml has no duplicate keys")
    void applicationYmlHasNoDuplicateKeys() throws Exception {
        loadStrict("src/main/resources/application.yml");
    }

    @Test
    @DisplayName("application-prod.yml has no duplicate keys (regression guard for api PR #62)")
    void applicationProdYmlHasNoDuplicateKeys() throws Exception {
        loadStrict("src/main/resources/application-prod.yml");
    }

    @Test
    @DisplayName("application-dev.yml has no duplicate keys")
    void applicationDevYmlHasNoDuplicateKeys() throws Exception {
        loadStrict("src/main/resources/application-dev.yml");
    }

    @Test
    @DisplayName("application-docker.yml has no duplicate keys")
    void applicationDockerYmlHasNoDuplicateKeys() throws Exception {
        loadStrict("src/main/resources/application-docker.yml");
    }

    /**
     * Parses the YAML at {@code path} with {@code allowDuplicateKeys=false}.
     * SnakeYAML throws {@link org.yaml.snakeyaml.parser.ParserException} on
     * a duplicate top-level or nested key, surfacing the exact line.
     */
    private static void loadStrict(String path) throws Exception {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setAllowDuplicateKeys(false);
        Yaml yaml = new Yaml(loaderOptions);
        try (InputStream is = Files.newInputStream(Paths.get(path))) {
            // Fully drain — multi-document YAMLs (rare for Spring Boot configs but
            // possible) must each pass the duplicate-key check.
            yaml.loadAll(is).forEach(d -> {});
        }
    }
}
