package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.SmartTransactionObject;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * #299 - regression test for the transaction mechanics of the auto-revoke.
 *
 * <p>The production symptom was a 500 from
 * {@code DELETE /api/v1/webauthn/credentials/by-id/{id}}: the credential delete
 * committed nothing because the caught {@code EntityNotFoundException} from the
 * same-transaction {@code ManageEnrollmentService.revokeEnrollment} marked the
 * shared transaction rollback-only, and the commit then threw
 * {@code UnexpectedRollbackException}.</p>
 *
 * <p>This test wires the REAL {@link WebAuthnCredentialService} and a real
 * {@code @Transactional} enrollment collaborator behind a real Spring
 * transaction interceptor, using a resource-less
 * {@link AbstractPlatformTransactionManager}. That reproduces the
 * rollback-only propagation without a database: with the old code the service
 * calls {@code revokeEnrollment} in the shared transaction, the collaborator
 * throws, the outer commit fails; with the fix the service calls
 * {@link ManageEnrollmentUseCase#revokeEnrollmentIfPresent}, which no-ops on a
 * missing row and runs in {@code REQUIRES_NEW}, so the delete commits.</p>
 */
@SpringJUnitConfig(WebAuthnCredentialDeleteTransactionTest.Config.class)
@DisplayName("#299 - last-passkey delete must not roll back on a missing enrollment row")
class WebAuthnCredentialDeleteTransactionTest {

    @Configuration
    @EnableTransactionManagement(proxyTargetClass = true)
    static class Config {

        @Bean
        PlatformTransactionManager transactionManager() {
            return new TestTransactionManager();
        }

        @Bean
        WebAuthnCredentialRepositoryPort credentialRepository() {
            return mock(WebAuthnCredentialRepositoryPort.class);
        }

        @Bean
        EnrollmentState enrollmentState() {
            return new EnrollmentState();
        }

        @Bean
        TestEnrollmentUseCase enrollmentUseCase(EnrollmentState enrollmentState) {
            return new TestEnrollmentUseCase(enrollmentState);
        }

        @Bean
        WebAuthnCredentialService webAuthnCredentialService(
                WebAuthnCredentialRepositoryPort credentialRepository,
                TestEnrollmentUseCase enrollmentUseCase) {
            return new WebAuthnCredentialService(credentialRepository, enrollmentUseCase);
        }
    }

    /** Mutable state shared with the transaction-proxied collaborator. */
    static class EnrollmentState {
        boolean enrollmentRowExists;
        boolean throwOnRevoke;
        int revokeCalls;
    }

    @Autowired
    private WebAuthnCredentialService service;

    @Autowired
    private WebAuthnCredentialRepositoryPort credentialRepository;

    @Autowired
    private EnrollmentState enrollmentState;

    @BeforeEach
    void resetState() {
        // The Spring context (and its state bean) is cached across test methods.
        enrollmentState.enrollmentRowExists = false;
        enrollmentState.throwOnRevoke = false;
        enrollmentState.revokeCalls = 0;
    }

    private WebAuthnCredential credential(UUID ownerId) {
        User owner = mock(User.class);
        when(owner.getId()).thenReturn(ownerId);

        WebAuthnCredential credential = mock(WebAuthnCredential.class);
        when(credential.getUser()).thenReturn(owner);
        when(credential.getTransports()).thenReturn("internal");
        return credential;
    }

    @Test
    @DisplayName("last platform credential + NO FINGERPRINT row ⇒ 204 path, delete commits, no revoke call")
    void deletingLastCredentialWithoutEnrollmentRowCommits() {
        UUID credentialId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        WebAuthnCredential credential = credential(ownerId);

        when(credentialRepository.findById(credentialId)).thenReturn(Optional.of(credential));
        when(credentialRepository.findAllByUserId(ownerId)).thenReturn(List.of());
        enrollmentState.enrollmentRowExists = false;
        enrollmentState.throwOnRevoke = true; // the old code would poison the transaction

        assertThatCode(() -> service.deleteById(credentialId))
                .as("a missing enrollment row must never roll back the credential delete")
                .doesNotThrowAnyException();

        verify(credentialRepository).deleteById(credentialId);
        assertThat(enrollmentState.revokeCalls).isZero();
    }

    @Test
    @DisplayName("a failure inside the auto-revoke is isolated in REQUIRES_NEW and cannot roll back the delete")
    void revokeFailureDoesNotRollBackTheDelete() {
        UUID credentialId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        WebAuthnCredential credential = credential(ownerId);

        when(credentialRepository.findById(credentialId)).thenReturn(Optional.of(credential));
        when(credentialRepository.findAllByUserId(ownerId)).thenReturn(List.of());
        enrollmentState.enrollmentRowExists = true;
        enrollmentState.throwOnRevoke = true; // the old same-transaction call would poison the commit

        assertThatCode(() -> service.deleteById(credentialId))
                .as("a failing best-effort revoke must not roll back the credential delete")
                .doesNotThrowAnyException();

        verify(credentialRepository).deleteById(credentialId);
        assertThat(enrollmentState.revokeCalls).isEqualTo(1);
    }

    @Test
    @DisplayName("last platform credential + existing FINGERPRINT row ⇒ revoke still runs (positive control)")
    void deletingLastCredentialWithEnrollmentRowRevokes() {
        UUID credentialId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        WebAuthnCredential credential = credential(ownerId);

        when(credentialRepository.findById(credentialId)).thenReturn(Optional.of(credential));
        when(credentialRepository.findAllByUserId(ownerId)).thenReturn(List.of());
        enrollmentState.enrollmentRowExists = true;
        enrollmentState.throwOnRevoke = false;

        assertThatCode(() -> service.deleteById(credentialId)).doesNotThrowAnyException();

        verify(credentialRepository).deleteById(credentialId);
        assertThat(enrollmentState.revokeCalls).isEqualTo(1);
    }

    /**
     * Real collaborator so its {@code @Transactional} proxy participates in the
     * caller's transaction exactly as the Spring bean does in production.
     */
    static class TestEnrollmentUseCase implements ManageEnrollmentUseCase {

        private final EnrollmentState state;

        TestEnrollmentUseCase(EnrollmentState state) {
            this.state = state;
        }

        @Override
        @Transactional(propagation = Propagation.REQUIRES_NEW)
        public void revokeEnrollmentIfPresent(UUID userId, AuthMethodType methodType) {
            if (!state.enrollmentRowExists) {
                return;
            }
            state.revokeCalls++;
            if (state.throwOnRevoke) {
                throw new EntityNotFoundException(
                        "Enrollment not found for user: " + userId + " method: " + methodType);
            }
        }

        @Override
        @Transactional
        public void revokeEnrollment(UUID userId, AuthMethodType methodType) {
            state.revokeCalls++;
            if (state.throwOnRevoke) {
                throw new EntityNotFoundException(
                        "Enrollment not found for user: " + userId + " method: " + methodType);
            }
        }

        @Override
        public List<EnrollmentResponse> getUserEnrollments(UUID userId) {
            return List.of();
        }

        @Override
        public EnrollmentResponse startEnrollment(UUID userId, UUID tenantId, AuthMethodType methodType) {
            return null;
        }

        @Override
        public EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData) {
            return null;
        }

        @Override
        public EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData,
                                                     BigDecimal qualityScore, BigDecimal livenessScore) {
            return null;
        }

        @Override
        public void recordBiometricScores(UUID userId, AuthMethodType methodType,
                                          BigDecimal qualityScore, BigDecimal livenessScore) {
            // no-op
        }

        @Override
        public void autoBindEnrollment(UUID userId, AuthMethodType methodType) {
            // no-op
        }
    }

    /**
     * Resource-less transaction manager that reproduces the one behaviour this
     * regression needs: when a participating {@code @Transactional} call fails,
     * the shared transaction is marked rollback-only and the outer commit throws
     * {@code UnexpectedRollbackException}. No database or connection is involved.
     */
    static class TestTransactionManager extends AbstractPlatformTransactionManager {

        private final ThreadLocal<TestTransaction> current = new ThreadLocal<>();

        @Override
        protected Object doGetTransaction() {
            TestTransaction transaction = current.get();
            return transaction != null ? transaction : new TestTransaction();
        }

        @Override
        protected boolean isExistingTransaction(Object transaction) {
            return ((TestTransaction) transaction).active;
        }

        /**
         * REQUIRES_NEW suspends the caller's transaction. Detach it so the inner
         * transaction starts with its own handle and cannot share rollback-only.
         */
        @Override
        protected Object doSuspend(Object transaction) {
            TestTransaction suspended = (TestTransaction) transaction;
            current.remove();
            return suspended;
        }

        @Override
        protected void doResume(Object transaction, Object suspendedResources) {
            current.set((TestTransaction) suspendedResources);
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
            TestTransaction testTransaction = (TestTransaction) transaction;
            testTransaction.active = true;
            testTransaction.rollbackOnly = false;
            current.set(testTransaction);
        }

        @Override
        protected void doSetRollbackOnly(DefaultTransactionStatus status) {
            ((TestTransaction) status.getTransaction()).rollbackOnly = true;
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            finish((TestTransaction) status.getTransaction());
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            finish((TestTransaction) status.getTransaction());
        }

        private void finish(TestTransaction transaction) {
            transaction.active = false;
            current.remove();
        }
    }

    /** Transaction handle; {@link SmartTransactionObject} exposes rollback-only to the outer commit. */
    static class TestTransaction implements SmartTransactionObject {

        boolean active;
        boolean rollbackOnly;

        @Override
        public boolean isRollbackOnly() {
            return rollbackOnly;
        }

        @Override
        public void flush() {
            // nothing to flush
        }
    }
}