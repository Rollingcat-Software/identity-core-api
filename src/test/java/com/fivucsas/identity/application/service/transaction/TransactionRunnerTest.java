package com.fivucsas.identity.application.service.transaction;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TransactionRunnerTest {

    private final TrackingTransactionManager transactionManager = new TrackingTransactionManager();
    private final TransactionRunner runner = new TransactionRunner(transactionManager);

    @Test
    void inTransaction_WhenWorkReturns_ShouldRunEffectsAfterCommitWithNoTransactionOpen() {
        List<String> seen = new ArrayList<>();

        String result = runner.inTransaction(effects -> {
            effects.afterCompletion(() -> seen.add("always, open=" + transactionManager.openTransactions()));
            effects.afterCommit(() -> seen.add("commit-only, open=" + transactionManager.openTransactions()));
            seen.add("work, open=" + transactionManager.openTransactions());
            return "done";
        });

        assertThat(result).isEqualTo("done");
        assertThat(seen).containsExactly("work, open=1", "always, open=0", "commit-only, open=0");
        assertThat(transactionManager.events()).containsExactly("begin", "commit");
    }

    @Test
    void inTransaction_WhenWorkThrows_ShouldRollBackRunAfterCompletionEffectsAndSkipCommitOnlyEffects() {
        List<String> seen = new ArrayList<>();
        IllegalStateException failure = new IllegalStateException("login refused");

        assertThatThrownBy(() -> runner.inTransaction(effects -> {
            effects.afterCompletion(() -> seen.add("failure audit, open=" + transactionManager.openTransactions()));
            effects.afterCommit(() -> seen.add("success audit"));
            throw failure;
        })).isSameAs(failure);

        assertThat(seen).containsExactly("failure audit, open=0");
        assertThat(transactionManager.events()).containsExactly("begin", "rollback");
    }

    @Test
    void inTransaction_WhenAnEffectFails_ShouldStillRunLaterEffectsAndKeepTheResult() {
        List<String> seen = new ArrayList<>();

        String result = runner.inTransaction(effects -> {
            effects.afterCompletion(() -> {
                throw new IllegalStateException("audit store down");
            });
            effects.afterCompletion(() -> seen.add("second"));
            return "done";
        });

        assertThat(result).isEqualTo("done");
        assertThat(seen).containsExactly("second");
    }

    @Test
    void inNewTransaction_WhenCalledInsideATransaction_ShouldCommitIndependentlyAndRunEffectsAfterIt() {
        List<String> seen = new ArrayList<>();

        runner.inTransaction(outer -> runner.inNewTransaction(inner -> {
            inner.afterCompletion(() -> seen.add("inner effect, open=" + transactionManager.openTransactions()));
            seen.add("inner work, open=" + transactionManager.openTransactions());
            return null;
        }));

        assertThat(seen).containsExactly("inner work, open=2", "inner effect, open=1");
        assertThat(transactionManager.events()).containsExactly("begin", "begin", "commit", "commit");
    }

    @Test
    void inTransaction_WhenJoinedOuterTransactionRollsBack_ShouldSkipCommitOnlyEffectsAndRunTheRestAfterTheOuterEnds() {
        List<String> seen = new ArrayList<>();
        TransactionTemplate outer = new TransactionTemplate(transactionManager);

        outer.executeWithoutResult(status -> {
            runner.inTransaction(effects -> {
                effects.afterCompletion(() -> seen.add("always, open=" + transactionManager.openTransactions()));
                effects.afterCommit(() -> seen.add("commit-only"));
                return null;
            });
            seen.add("outer continues");
            status.setRollbackOnly();
        });

        assertThat(seen).containsExactly("outer continues", "always, open=0");
        assertThat(transactionManager.events()).containsExactly("begin", "rollback");
    }

    @Test
    void inTransaction_WhenJoinedOuterTransactionCommits_ShouldRunEffectsOnlyAfterTheOuterCommit() {
        List<String> seen = new ArrayList<>();
        TransactionTemplate outer = new TransactionTemplate(transactionManager);

        outer.executeWithoutResult(status -> {
            runner.inTransaction(effects -> {
                effects.afterCommit(() -> seen.add("commit-only, open=" + transactionManager.openTransactions()));
                return null;
            });
            seen.add("outer continues");
        });

        assertThat(seen).containsExactly("outer continues", "commit-only, open=0");
        assertThat(transactionManager.events()).containsExactly("begin", "commit");
    }
}
