package com.fivucsas.identity.application.service.transaction;

import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Resource-less transaction manager for unit tests. It runs Spring's real
 * propagation logic and records what happened, so a test can assert that some
 * call ran (or did not run) while a transaction was open.
 */
public class TrackingTransactionManager extends AbstractPlatformTransactionManager {

    private int openTransactions;
    private final List<String> events = new ArrayList<>();

    /** Number of physical transactions currently open (a REQUIRES_NEW inside another counts as two). */
    public int openTransactions() {
        return openTransactions;
    }

    /** Begin / commit / rollback events in order, e.g. {@code ["begin", "commit"]}. */
    public List<String> events() {
        return events;
    }

    @Override
    protected Object doGetTransaction() {
        return new Object();
    }

    @Override
    protected boolean isExistingTransaction(Object transaction) {
        return openTransactions > 0;
    }

    @Override
    protected void doBegin(Object transaction, TransactionDefinition definition) {
        openTransactions++;
        events.add("begin");
    }

    @Override
    protected Object doSuspend(Object transaction) {
        return Boolean.TRUE;
    }

    @Override
    protected void doResume(Object transaction, Object suspendedResources) {
        // nothing bound, nothing to restore
    }

    @Override
    protected void doCommit(DefaultTransactionStatus status) {
        openTransactions--;
        events.add("commit");
    }

    @Override
    protected void doSetRollbackOnly(DefaultTransactionStatus status) {
        events.add("rollback-only");
    }

    @Override
    protected void doRollback(DefaultTransactionStatus status) {
        openTransactions--;
        events.add("rollback");
    }
}
