package com.fivucsas.identity.application.port.input;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.UUID;

/**
 * Driving port of the authors-only trial surface (V90,
 * docs/AUTHOR_TRIAL_CONTRACT.md). The controller is the only caller; the
 * service owns validation, the server-side round plan and the real MFA session
 * creation.
 */
public interface AuthorTrialUseCase {

    /** POST /session body. Device/environment are raw JSON, sanitised by the service. */
    record StartRequest(String participantCode,
                        String mode,
                        String targetCode,
                        String instrument,
                        String instrumentPreset,
                        JsonNode device,
                        JsonNode env,
                        String webVersion) {}

    /** POST /attempts/{id}/finish body. */
    record FinishRequest(String clientOutcome,
                         Integer clientLatencyMs,
                         String failureReason,
                         JsonNode device,
                         JsonNode env) {}

    /** POST /enroll body. */
    record EnrollRequest(String participantCode, List<Double> embedding, String webVersion) {}

    record ParticipantView(String code, boolean enrolled) {}

    record FlowView(String method, boolean binding, String difficulty, int count, List<String> challenges) {}

    record ParticipantsView(UUID tenantId, List<ParticipantView> participants, FlowView flow) {}

    record PuzzleConfigView(List<String> allowedChallengeTypes,
                            int count,
                            String difficulty,
                            boolean alsoMatchFaceIdentity) {}

    record SessionView(UUID attemptId,
                       String mfaSessionToken,
                       String participantCode,
                       String targetCode,
                       String mode,
                       int round,
                       int position,
                       String challenge,
                       boolean binding,
                       String difficulty,
                       int count,
                       PuzzleConfigView puzzleConfig) {}

    record FinishView(String outcome, boolean excluded, String failureReason) {}

    record EnrollView(boolean enrolled) {}

    record ExportView(String body, String contentType, String filename) {}

    ParticipantsView participants();

    SessionView startSession(StartRequest request, String clientIp, String userAgent);

    FinishView finish(UUID attemptId, FinishRequest request);

    EnrollView enroll(EnrollRequest request);

    ExportView export(String format);
}