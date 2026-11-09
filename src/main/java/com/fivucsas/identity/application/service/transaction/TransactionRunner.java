package com.fivucsas.identity.application.service.transaction;

import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.function.Function;

/**
 * Runs a unit of work in a transaction and, after that transaction has ended, the
 * side effects the work deferred through {@link DeferredEffects}.
 *
 * <p>Why it exists (identity-core-api #285): code that calls a {@code REQUIRES_NEW}
 * method, or makes an outbound HTTP call, from inside a transaction holds one pooled
 * connection while it waits for a second one or for the network. Enough of those in
 * parallel deadlock the Hikari pool. Splitting the work into short transactions and
 * running audit writes and remote calls between them keeps every thread at one
 * connection at most.</p>
 *
 * <p>When no transaction is active on entry, the deferred effects run after the new
 * transaction has committed or rolled back and its connection has been released
 * (with open-in-view off for the calling request). When the caller already holds a
 * transaction, {@link #inTransaction} joins it and the effects run when the work
 * returns, so the connection is still the caller's; only the outermost caller
 * decides when connections are released.</p>
 */
@Component
public class TransactionRunner {

    private final TransactionTemplate required;
    private final TransactionTemplate requiresNew;

    public TransactionRunner(PlatformTransactionManager transactionManager) {
        this.required = new TransactionTemplate(transactionManager);
        this.requiresNew = new TransactionTemplate(transactionManager);
        this.requiresNew.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /** Runs {@code work} in the current transaction, or in a new one when none is active. */
    public <T> T inTransaction(Function<DeferredEffects, T> work) {
        return run(required, work);
    }

    /**
     * Runs {@code work} in its own transaction that commits independently of any caller
     * transaction, for state that must survive the caller rolling back (for example a
     * failed-login strike counter).
     */
    public <T> T inNewTransaction(Function<DeferredEffects, T> work) {
        return run(requiresNew, work);
    }

    private static <T> T run(TransactionTemplate template, Function<DeferredEffects, T> work) {
        DeferredEffects effects = new DeferredEffects();
        boolean committed = false;
        try {
            T result = template.execute(status -> work.apply(effects));
            committed = true;
            return result;
        } finally {
            effects.runAll(committed);
        }
    }
}
