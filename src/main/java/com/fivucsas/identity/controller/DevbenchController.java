package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ExportDevbenchRunsUseCase;
import com.fivucsas.identity.application.port.input.SubmitDevbenchRunUseCase;
import com.fivucsas.identity.application.service.devbench.DevbenchRunSanitizer;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Paper A device benchmark (app.fivucsas.com/devbench).
 *
 * <ul>
 *   <li>{@code POST /api/v1/devbench/runs}: PUBLIC and write-only. Anyone can submit a run,
 *       nobody can read one back here. Permit-all in SecurityConfig, per-IP capped in
 *       RateLimitFilter, body capped at {@value DevbenchRunSanitizer#MAX_BODY_BYTES} bytes
 *       before parsing.</li>
 *   <li>{@code GET /api/v1/admin/devbench/runs?format=json|csv}: ROOT only, full export.</li>
 * </ul>
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Device benchmark", description = "Anonymous on-device model timing runs (research)")
public class DevbenchController {

    private final SubmitDevbenchRunUseCase submitUseCase;
    private final ExportDevbenchRunsUseCase exportUseCase;

    @PostMapping(value = "/api/v1/devbench/runs", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Submit one benchmark run (public, write-only, rate-limited)")
    public ResponseEntity<Map<String, Object>> submit(HttpServletRequest request) throws IOException {
        if (request.getContentLengthLong() > DevbenchRunSanitizer.MAX_BODY_BYTES) {
            return status(HttpStatus.PAYLOAD_TOO_LARGE, "body_too_large");
        }
        byte[] body = readBounded(request.getInputStream(), DevbenchRunSanitizer.MAX_BODY_BYTES);
        if (body == null) {
            return status(HttpStatus.PAYLOAD_TOO_LARGE, "body_too_large");
        }
        return switch (submitUseCase.submit(body)) {
            case SubmitDevbenchRunUseCase.Stored s ->
                    ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", s.id().toString()));
            case SubmitDevbenchRunUseCase.Rejected r -> status(HttpStatus.BAD_REQUEST, r.reason());
            case SubmitDevbenchRunUseCase.OverDailyCap c -> ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(HttpHeaders.RETRY_AFTER, "3600").body(Map.of("error", "daily_cap"));
            case SubmitDevbenchRunUseCase.Disabled d -> status(HttpStatus.SERVICE_UNAVAILABLE, "disabled");
        };
    }

    @GetMapping("/api/v1/admin/devbench/runs")
    @PreAuthorize("@rbac.isRoot()")
    @Operation(summary = "Export every benchmark run (ROOT only)")
    public ResponseEntity<String> export(@RequestParam(defaultValue = "json") String format) {
        boolean csv = "csv".equals(format);
        String body = csv ? exportUseCase.exportCsv() : exportUseCase.exportJson();
        String filename = csv ? "devbench_runs.csv" : "devbench_runs.json";
        return ResponseEntity.ok()
                .contentType(csv ? new MediaType("text", "csv", StandardCharsets.UTF_8) : MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(body);
    }

    /** Reads at most {@code max} bytes; returns null when the stream holds more (chunked bodies have no length). */
    static byte[] readBounded(InputStream in, int max) throws IOException {
        byte[] data = in.readNBytes(max + 1);
        return data.length > max ? null : data;
    }

    private static ResponseEntity<Map<String, Object>> status(HttpStatus status, String error) {
        return ResponseEntity.status(status).body(Map.of("error", error));
    }
}
