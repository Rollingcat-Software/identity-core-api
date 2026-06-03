package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.BiometricEnrollmentReconciler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * ROOT-only endpoint to reconcile the denormalized
 * {@code users.is_biometric_enrolled} flag against the bio face store.
 *
 * <p>Repairs the "enrolled-but-412" class: users who have a real FACE embedding
 * in the biometric-processor store but whose flag is stale {@code false}, so
 * {@code /biometric/verify} rejects them with HTTP 412 "not enrolled". The
 * inconsistent write paths that produced these users are fixed; this operation
 * cleans up the rows already left behind.</p>
 *
 * <p><b>Dry-run by default.</b> Without {@code apply=true} the endpoint only
 * PREVIEWS what would change (no rows written). Operators must inspect the
 * dry-run output and then re-call with {@code apply=true} to write. The operation
 * is idempotent and only ever flips {@code false → true} for users with a
 * CONFIRMED embedding (fail-closed on any bio error) — it can never lock a user
 * out of verify.</p>
 */
@RestController
@RequestMapping("/api/v1/admin/biometric")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin — Biometric Reconcile",
        description = "Reconcile is_biometric_enrolled flags against the bio embedding store")
public class BiometricReconcileAdminController {

    private final BiometricEnrollmentReconciler reconciler;

    @PostMapping("/reconcile-enrollment-flags")
    @Operation(summary = "Reconcile is_biometric_enrolled flags against the bio embedding store",
            description = "DRY-RUN by default: previews how many users have a real bio embedding but "
                    + "is_biometric_enrolled=false (the 'enrolled-but-412' set) WITHOUT writing. "
                    + "Pass apply=true to actually flip those flags to true. Idempotent; only ever "
                    + "sets false→true for users with a confirmed embedding (fail-closed).")
    @PreAuthorize("@rbac.isRoot()")
    public ResponseEntity<Map<String, Object>> reconcileEnrollmentFlags(
            @RequestParam(value = "apply", required = false, defaultValue = "false") boolean apply) {
        log.info("POST /api/v1/admin/biometric/reconcile-enrollment-flags - ROOT reconcile (apply={})", apply);

        // dryRun is the inverse of apply: apply=false → preview only.
        BiometricEnrollmentReconciler.ReconcileResult result = reconciler.reconcile(!apply);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dryRun", result.dryRun());
        body.put("scanned", result.scanned());
        body.put("wouldUpdate", result.wouldUpdate());
        body.put("updated", result.updated());
        body.put("affectedIds", result.affectedIds().stream().map(UUID::toString).toList());
        return ResponseEntity.ok(body);
    }
}
