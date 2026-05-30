package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.SoftDeletePurgeJob;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Super-admin endpoints for the GDPR/KVKK soft-delete purge job.
 *
 * <p>The dry-run endpoint returns what WOULD be permanently deleted under the current
 * 30-day retention window without modifying any rows. Operators must verify the
 * dry-run output BEFORE flipping {@code app.purge.softDelete.enabled=true}.</p>
 */
@RestController
@RequestMapping("/api/v1/admin/purge")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin — GDPR Purge", description = "Soft-delete retention + permanent purge operations")
public class PurgeAdminController {

    private final SoftDeletePurgeJob softDeletePurgeJob;

    @DeleteMapping("/dry-run")
    @Operation(summary = "Preview soft-delete purge candidates (no data modified)",
               description = "Returns the cutoff timestamp, count, and user IDs that WOULD be permanently "
                   + "purged under the 30-day retention window. Use this before enabling the scheduled job.")
    @PreAuthorize("@rbac.isRoot()")
    public ResponseEntity<Map<String, Object>> dryRun() {
        log.info("DELETE /api/v1/admin/purge/dry-run - super-admin previewing purge candidates");
        SoftDeletePurgeJob.DryRunResult result = softDeletePurgeJob.dryRun();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cutoff", result.cutoff().toString());
        body.put("candidateCount", result.candidateCount());
        body.put("candidateIds", result.candidateIds().stream().map(java.util.UUID::toString).toList());
        body.put("featureFlagEnabled", softDeletePurgeJob.isEnabled());
        body.put("retentionDays", SoftDeletePurgeJob.RETENTION_WINDOW.toDays());
        return ResponseEntity.ok(body);
    }
}
