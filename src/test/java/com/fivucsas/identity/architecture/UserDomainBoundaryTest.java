package com.fivucsas.identity.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.ArchTag;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Enforces the hexagonal-architecture boundary around the {@code User} aggregate.
 *
 * <p>Background: the codebase has two {@code User} types alive in production —
 * {@code domain.model.user.User} (pure-domain target, ~6 import sites) and
 * {@code entity.User} (JPA persistence model, dozens of legacy import sites). The
 * approved migration plan (see {@code ANALYSIS_2026-05-02_USER_DOMAIN_AND_JWT_ROTATION.md},
 * § "User domain") is option (a): keep both, route NEW application/controller code through
 * the pure-domain via {@code UserDomainRepository}, and use this ArchUnit test as the
 * ratchet that prevents regression.
 *
 * <p>Allow-list — packages permitted to import {@code entity.User}:
 * <ul>
 *   <li>{@code com.fivucsas.identity.entity..} — JPA siblings (FK references, @ManyToOne).</li>
 *   <li>{@code com.fivucsas.identity.repository..} — Spring Data {@code JpaRepository<User, …>}.</li>
 *   <li>{@code com.fivucsas.identity.infrastructure..} — adapters / mappers, the official bridge.</li>
 *   <li>{@code com.fivucsas.identity.IdentityCoreApiApplication} — Spring Boot main (entity scan).</li>
 *   <li>{@code com.fivucsas.identity.security..} — {@code CustomUserDetailsService} bridge into Spring Security.</li>
 * </ul>
 *
 * <p>Forbidden — explicitly callouts: {@code application..} (services / handlers / mappers /
 * ports) and {@code controller..} (REST layer). New code in those packages must use
 * {@code domain.model.user.User} via {@code UserDomainRepository}.
 *
 * <p>Strategy: {@link FreezingArchRule#freeze} records the current set of violations as a
 * baseline on first run; subsequent runs only fail on NEW violations. This is the canonical
 * ratchet pattern. The baseline file is checked in under {@code archunit_store/} so CI
 * has a stable snapshot. Migrating an existing violation is a normal PR — delete the
 * matching line from {@code archunit_store/user_domain_boundary.txt} and the baseline shrinks.
 *
 * <p>Tag {@code @ArchTag("user-domain-boundary")} lets operators exclude this test in an
 * emergency:
 * {@code mvn test -Djunit.jupiter.tags="!user-domain-boundary"}.
 */
@ArchTag("user-domain-boundary")
class UserDomainBoundaryTest {

    /** Whole-module import; tests are excluded so the rule scopes only to production code. */
    private static final JavaClasses PRODUCTION_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_JARS)
            .importPackages("com.fivucsas.identity");

    @Test
    void noNewClassesOutsideAllowListMayDependOnEntityUser() {
        ArchRule rule = noClasses()
                .that()
                .resideOutsideOfPackages(
                        "com.fivucsas.identity.entity..",
                        "com.fivucsas.identity.repository..",
                        "com.fivucsas.identity.infrastructure..",
                        "com.fivucsas.identity.security.."
                )
                .and().doNotHaveFullyQualifiedName(
                        "com.fivucsas.identity.IdentityCoreApiApplication")
                .should()
                .dependOnClassesThat()
                .haveFullyQualifiedName("com.fivucsas.identity.entity.User")
                .because(
                    "Hexagonal boundary: new application/controller code must use "
                  + "domain.model.user.User via UserDomainRepository. "
                  + "See ANALYSIS_2026-05-02_USER_DOMAIN_AND_JWT_ROTATION.md.");

        // Ratchet: existing violations are frozen as a baseline; only NEW ones fail.
        FreezingArchRule.freeze(rule).check(PRODUCTION_CLASSES);
    }
}
