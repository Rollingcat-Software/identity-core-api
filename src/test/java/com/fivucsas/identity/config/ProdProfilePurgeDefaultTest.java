package com.fivucsas.identity.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for T2-E (INVESTIGATION_MASTER_2026-05-07 P1):
 * {@code application-prod.yml} must default {@code app.purge.softDelete.enabled}
 * to {@code true} so GDPR Art. 17 / KVKK right-to-erasure actually executes in
 * production when the env-var is unset.
 *
 * <p>Pairs with {@link YamlProfileConfigTest} (which only checks duplicate-key
 * hygiene) by pinning the resolved placeholder default. If someone toggles the
 * prod default back to {@code false} or removes the {@code app.purge.softDelete.enabled}
 * key entirely, this test fails loudly.
 *
 * <p>The base {@code application.yml} default remains {@code false} so non-prod
 * profiles do not silently purge dev data — that invariant is also asserted here.
 */
@DisplayName("application-prod.yml — app.purge.softDelete.enabled default-on")
class ProdProfilePurgeDefaultTest {

    @Test
    @DisplayName("prod profile: app.purge.softDelete.enabled placeholder default is true")
    void prodPurgeDefaultIsTrue() throws Exception {
        String resolved = readPurgePlaceholder("src/main/resources/application-prod.yml");
        // Format: ${APP_PURGE_SOFT_DELETE_ENABLED:true}
        assertThat(resolved)
                .as("prod profile MUST default-on so GDPR Art. 17 hard-purge runs " +
                        "without operator hand-edits of .env.prod")
                .endsWith(":true}");
        assertThat(resolved)
                .as("env-var key must stay APP_PURGE_SOFT_DELETE_ENABLED — docker-compose wires this exact name")
                .startsWith("${APP_PURGE_SOFT_DELETE_ENABLED:");
    }

    @Test
    @DisplayName("base application.yml: app.purge.softDelete.enabled placeholder default stays false")
    void basePurgeDefaultStaysFalse() throws Exception {
        String resolved = readPurgePlaceholder("src/main/resources/application.yml");
        assertThat(resolved)
                .as("base profile MUST default-off so dev fixtures do not silently purge test data")
                .endsWith(":false}");
        assertThat(resolved)
                .startsWith("${APP_PURGE_SOFT_DELETE_ENABLED:");
    }

    @SuppressWarnings("unchecked")
    private static String readPurgePlaceholder(String path) throws Exception {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setAllowDuplicateKeys(false);
        Yaml yaml = new Yaml(loaderOptions);
        try (InputStream is = Files.newInputStream(Paths.get(path))) {
            Map<String, Object> root = yaml.load(is);
            Map<String, Object> app = (Map<String, Object>) root.get("app");
            assertThat(app).as("`app:` block missing from " + path).isNotNull();
            Map<String, Object> purge = (Map<String, Object>) app.get("purge");
            assertThat(purge).as("`app.purge` block missing from " + path).isNotNull();
            Map<String, Object> softDelete = (Map<String, Object>) purge.get("softDelete");
            assertThat(softDelete).as("`app.purge.softDelete` block missing from " + path).isNotNull();
            Object enabled = softDelete.get("enabled");
            assertThat(enabled)
                    .as("`app.purge.softDelete.enabled` key missing from " + path)
                    .isNotNull();
            return enabled.toString();
        }
    }
}
