package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.AuthorTrialUseCase;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialAccessGuard;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Authors-only trial surface for Paper B (V90).
 *
 * <p>Public in Spring Security but gated by the {@code X-Author-Trial-Key}
 * shared key plus the feature flag + single-tenant allow-list: a disabled or
 * unconfigured surface answers 404, a wrong key 401. The page has no user login;
 * the key only opens the research surface, never an account. The attempts run
 * the REAL PUZZLE + face-identity MFA path.
 */
@RestController
@RequestMapping("/api/v1/author-trial")
@RequiredArgsConstructor
@Tag(name = "Author trial", description = "Authors-only Paper B trial (pseudonymous, access-key gated)")
public class AuthorTrialController {

    public static final String KEY_HEADER = "X-Author-Trial-Key";

    private final AuthorTrialUseCase useCase;
    private final AuthorTrialAccessGuard accessGuard;

    @GetMapping("/participants")
    @Operation(summary = "List the configured pseudonymous participants and the trial flow")
    public ResponseEntity<AuthorTrialUseCase.ParticipantsView> participants(
            @RequestHeader(value = KEY_HEADER, required = false) String key) {
        requireAccess(key);
        return ResponseEntity.ok(useCase.participants());
    }

    @PostMapping(value = "/session", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Open one trial attempt on the real MFA path")
    public ResponseEntity<AuthorTrialUseCase.SessionView> startSession(
            @RequestHeader(value = KEY_HEADER, required = false) String key,
            @RequestBody AuthorTrialUseCase.StartRequest request,
            HttpServletRequest http) {
        requireAccess(key);
        return ResponseEntity.ok(useCase.startSession(request,
                http.getRemoteAddr(), http.getHeader(HttpHeaders.USER_AGENT)));
    }

    @PostMapping(value = "/attempts/{attemptId}/finish", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Record the technical finish status of a trial attempt")
    public ResponseEntity<AuthorTrialUseCase.FinishView> finish(
            @RequestHeader(value = KEY_HEADER, required = false) String key,
            @PathVariable UUID attemptId,
            @RequestBody AuthorTrialUseCase.FinishRequest request) {
        requireAccess(key);
        return ResponseEntity.ok(useCase.finish(attemptId, request));
    }

    @PostMapping(value = "/enroll", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "One-time face + PUZZLE enrollment for a pseudonymous participant")
    public ResponseEntity<AuthorTrialUseCase.EnrollView> enroll(
            @RequestHeader(value = KEY_HEADER, required = false) String key,
            @RequestBody AuthorTrialUseCase.EnrollRequest request) {
        requireAccess(key);
        return ResponseEntity.ok(useCase.enroll(request));
    }

    @GetMapping("/export")
    @Operation(summary = "Export the trial attempts (sessions.csv schema + documented extension)")
    public ResponseEntity<String> export(
            @RequestHeader(value = KEY_HEADER, required = false) String key,
            @RequestParam(defaultValue = "csv") String format) {
        requireAccess(key);
        AuthorTrialUseCase.ExportView view = useCase.export(format);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(view.contentType()))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + view.filename() + "\"")
                .cacheControl(CacheControl.noStore())
                .body(view.body());
    }

    private void requireAccess(String key) {
        if (!accessGuard.surfaceEnabled()) {
            // Hide the surface entirely when it is not configured.
            throw AuthorTrialException.notFound("AUTHOR_TRIAL_DISABLED");
        }
        if (!accessGuard.keyMatches(key)) {
            throw AuthorTrialException.unauthorized("TRIAL_KEY_INVALID");
        }
    }
}