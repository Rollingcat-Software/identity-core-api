package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Repairs the denormalized {@code users.is_biometric_enrolled} flag for users who
 * actually have a FACE embedding in the biometric-processor's face store but whose
 * flag is (incorrectly) {@code false}.
 *
 * <p><b>Why this exists.</b> The biometric platform keeps the truth about an
 * enrollment in TWO places: the embedding row in the bio face store (separate
 * database, owned by biometric-processor) and the {@code is_biometric_enrolled}
 * boolean in {@code identity_core.users}. {@code VerifyBiometricService} gates
 * verify on that boolean and throws {@code BiometricNotEnrolledException} → HTTP
 * 412 when it is {@code false}. Historically several enroll paths persisted the
 * embedding but failed to flip the flag (the non-transactional multi-enroll, and
 * the legacy {@code EnrollmentController.submitEnrollment}), producing
 * "enrolled-but-412" users. Those write paths are now fixed; this reconciler
 * repairs the users that were already left in the inconsistent state.</p>
 *
 * <p><b>Safety contract.</b> The operation is:
 * <ul>
 *   <li><b>idempotent</b> — running it twice changes nothing the second time; it
 *       only ever flips {@code false → true}, only for users with a CONFIRMED bio
 *       enrollment, and skips users already flagged {@code true};</li>
 *   <li><b>dry-run-able</b> — {@link #reconcile(boolean) reconcile(true)} computes
 *       and returns exactly what WOULD change WITHOUT writing anything;</li>
 *   <li><b>fail-closed</b> — it flips a flag only when
 *       {@link BiometricServicePort#hasEnrollment} CONFIRMS an embedding; any bio
 *       transport error yields {@code false} there, so an unconfirmed user is
 *       never flipped. It never sets a flag to {@code false} (that is the
 *       responsibility of the delete / health-revoke paths), so it cannot lock a
 *       user out of verify.</li>
 * </ul>
 * It is exposed only through a ROOT-gated admin endpoint and is intended to be run
 * deliberately by an operator — never automatically.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BiometricEnrollmentReconciler {

    private final UserDomainRepository userDomainRepository;
    private final BiometricServicePort biometricServicePort;

    /**
     * Result of a reconciliation pass.
     *
     * @param dryRun       whether this was a preview (no writes) or an applied run
     * @param scanned      number of users examined (those with the flag currently false)
     * @param wouldUpdate  users that have a confirmed bio enrollment but flag=false
     *                     (in a dry run this is the count that WOULD be flipped; in
     *                     an applied run this is the count that WAS flipped)
     * @param updated      users actually flipped to true (0 on a dry run)
     * @param affectedIds  the ids of the would-update / updated users
     */
    public record ReconcileResult(boolean dryRun,
                                  long scanned,
                                  long wouldUpdate,
                                  long updated,
                                  List<UUID> affectedIds) {}

    /**
     * Scans every user whose {@code is_biometric_enrolled} flag is {@code false}
     * and, for each one that the bio store confirms holds a FACE embedding, flips
     * the flag to {@code true} (unless {@code dryRun}).
     *
     * @param dryRun when {@code true}, computes and returns the candidate set
     *               WITHOUT writing any rows; when {@code false}, applies the fix
     * @return the reconciliation result (counts + affected ids)
     */
    @Transactional
    public ReconcileResult reconcile(boolean dryRun) {
        // Only users whose flag is currently false can be "enrolled-but-412".
        // Users already flagged true are left untouched → idempotent.
        List<User> candidates = userDomainRepository.findByIsBiometricEnrolled(false);
        log.info("Biometric-enrollment reconcile starting (dryRun={}): {} users with flag=false",
                dryRun, candidates.size());

        List<UUID> affected = new ArrayList<>();
        long updated = 0;

        for (User user : candidates) {
            String tenantId = user.getTenantId() != null ? user.getTenantId().toString() : null;
            boolean reallyEnrolled;
            try {
                reallyEnrolled = biometricServicePort.hasEnrollment(user.getId(), tenantId);
            } catch (Exception e) {
                // Defensive: the port already fails closed, but never let one
                // user's bio hiccup abort the whole pass.
                log.warn("hasEnrollment threw for user {} (tenant {}) — skipping: {}",
                        user.getId(), tenantId, e.getMessage());
                continue;
            }

            if (!reallyEnrolled) {
                continue;
            }

            affected.add(user.getId());
            if (!dryRun) {
                user.enrollBiometric();
                userDomainRepository.save(user);
                updated++;
                log.info("Reconciled is_biometric_enrolled=true for user {} (confirmed bio embedding)",
                        user.getId());
            }
        }

        ReconcileResult result = new ReconcileResult(
                dryRun, candidates.size(), affected.size(), updated, affected);
        log.info("Biometric-enrollment reconcile finished: {}", result);
        return result;
    }
}
