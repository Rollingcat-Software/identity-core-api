package com.fivucsas.identity.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure-parse smoke (#37, 2026-05-21) for {@code application-prod.yml}: every
 * Spring {@code ${ENV}} placeholder must either carry a {@code :default} (so
 * Spring can always resolve it) or be one of a small allowlist of vars the
 * operator is required to provide at deploy time (DB credentials).
 *
 * <p>Without this guard, adding a new {@code ${SOME_VAR}} with no default and
 * no operator-provisioning becomes an unresolvable-placeholder crash at Spring
 * Boot startup — caught only in prod. This test catches it at unit-test time.
 *
 * <p>Deliberately does NOT load the Spring context (no {@code @SpringBootTest}):
 * it scans the raw file text, so it stays CI-cheap and matches the
 * {@link YamlProfileConfigTest} pure-parse pattern.
 */
@DisplayName("application-prod.yml placeholder resolvability smoke")
class ProdYamlPlaceholderResolvableTest {

    private static final String PROD_YML = "src/main/resources/application-prod.yml";

    /**
     * Vars intentionally left without a {@code :default} in application-prod.yml
     * because the operator MUST provide them (no safe fallback exists). Adding a
     * new no-default placeholder requires a conscious entry here, which forces a
     * reviewer to confirm the deploy tooling actually supplies it.
     */
    private static final Set<String> OPERATOR_PROVIDED_ALLOWLIST = Set.of(
            "DATABASE_URL",
            "DATABASE_USERNAME",
            "DATABASE_PASSWORD"
    );

    // Matches a single ${...} placeholder body (no nesting in this file; asserted below).
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

    @Test
    @DisplayName("every ${ENV} either has a :default or is an allowlisted operator-provided var")
    void everyPlaceholderResolvable() throws Exception {
        String content = Files.readString(Paths.get(PROD_YML));

        // Guard the simplifying assumption of the body regex: no nested ${...}.
        assertTrue(!Pattern.compile("\\$\\{[^}]*\\$\\{").matcher(content).find(),
                "Nested ${...${...}} placeholder found in " + PROD_YML
                        + " — update this test's parser before relying on it.");

        Set<String> unresolvable = new LinkedHashSet<>();
        Matcher m = PLACEHOLDER.matcher(content);
        while (m.find()) {
            String body = m.group(1);
            int colon = body.indexOf(':');
            if (colon >= 0) {
                // Has a default segment (which may legitimately be empty, e.g.
                // ${BIOMETRIC_SERVICE_API_KEY:}). Resolvable.
                continue;
            }
            String varName = body.trim();
            if (!OPERATOR_PROVIDED_ALLOWLIST.contains(varName)) {
                unresolvable.add(varName);
            }
        }

        assertTrue(unresolvable.isEmpty(),
                "application-prod.yml has ${ENV} placeholders with no :default and "
                        + "not in the operator-provided allowlist: " + unresolvable
                        + ". Either add a :default, or (if the operator must supply it) "
                        + "add the var name to OPERATOR_PROVIDED_ALLOWLIST in this test.");
    }
}
