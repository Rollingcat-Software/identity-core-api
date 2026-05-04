package com.fivucsas.identity.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.ArchTag;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Closes T-SEC-TAIL §T4.4 (2026-05-04): forbid controllers and auth handlers
 * from calling {@code WebAuthnCredentialRepositoryPort} write methods directly.
 * Three direct {@code credentialRepository.save(...)} writes lived in
 * {@code DeviceController} plus two more in
 * {@code HardwareKeyAuthHandler} / {@code FingerprintAuthHandler} and one in
 * {@code WebAuthnVerifySupport}, all sidestepping the
 * {@code WebAuthnCredentialService} transaction boundary and its
 * auto-enrollment side-effect.
 *
 * <p>Peer application services (notably {@code ManageEnrollmentService}) are
 * deliberately exempt: they implement the inverse enrollment-revoke lifecycle
 * and routing them through the service would be circular.</p>
 *
 * <p>Tag {@code @ArchTag("webauthn-write-boundary")} lets operators exclude
 * the test in an emergency:
 * {@code mvn test -Djunit.jupiter.tags="!webauthn-write-boundary"}.</p>
 */
@ArchTag("webauthn-write-boundary")
class WebAuthnRepoWriteBoundaryTest {

    private static final JavaClasses PRODUCTION_CLASSES = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_JARS)
            .importPackages("com.fivucsas.identity");

    @Test
    void controllersAndAuthHandlersMustNotCallRepositoryWritePortMethods() {
        ArchRule rule = noClasses()
                .that()
                .resideInAnyPackage(
                        "com.fivucsas.identity.controller..",
                        "com.fivucsas.identity.application.service.handler..",
                        "com.fivucsas.identity.application.service.mfa.handler..")
                .should()
                .callMethod(
                        "com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort",
                        "save",
                        "com.fivucsas.identity.entity.WebAuthnCredential")
                .orShould()
                .callMethod(
                        "com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort",
                        "deleteById",
                        "java.util.UUID")
                .orShould()
                .callMethod(
                        "com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort",
                        "deleteByCredentialId",
                        "java.lang.String")
                .because(
                        "Controllers and auth handlers must route WebAuthn credential "
                      + "writes through WebAuthnCredentialService, which owns the "
                      + "auto-enrollment side-effect and @Transactional boundary "
                      + "(T-SEC-TAIL §T4.4, 2026-05-04).");

        rule.check(PRODUCTION_CLASSES);
    }
}
