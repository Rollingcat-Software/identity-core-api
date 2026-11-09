package com.fivucsas.identity.application.service.transaction;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

/**
 * Side effects that a unit of work queues while its transaction is open and that
 * {@link TransactionRunner} runs once that transaction has ended.
 *
 * <p>Typical use: an audit row written through a {@code REQUIRES_NEW} adapter. Run
 * inside the caller's transaction it needs a second pooled connection while the
 * first is still held (identity-core-api #285); deferred, it runs on its own single
 * connection after the caller's connection is back in the pool.</p>
 *
 * <p>Effects run in the order they were queued. A failing effect is logged and does
 * not stop the others, and it never replaces the outcome of the work itself.</p>
 */
@Slf4j
public final class DeferredEffects {

    private record Effect(Runnable action, boolean commitOnly) {
    }

    private final List<Effect> effects = new ArrayList<>();

    DeferredEffects() {
    }

    /**
     * Runs {@code effect} after the transaction ends (the caller's transaction when the
     * work joined one), whether it committed or rolled back. Use it for records that
     * must survive a rollback, such as a failed-login audit row written right before
     * the work throws.
     */
    public void afterCompletion(Runnable effect) {
        effects.add(new Effect(effect, false));
    }

    /**
     * Runs {@code effect} only if the transaction the work ran in committed. When the
     * work joined a caller's transaction, that is the caller's transaction: the effect
     * waits for its commit and is skipped if it rolls back.
     */
    public void afterCommit(Runnable effect) {
        effects.add(new Effect(effect, true));
    }

    void runAll(boolean committed) {
        for (Effect effect : effects) {
            if (effect.commitOnly() && !committed) {
                continue;
            }
            try {
                effect.action().run();
            } catch (RuntimeException e) {
                log.error("Deferred post-transaction effect failed: {}", e.getMessage(), e);
            }
        }
        effects.clear();
    }
}
