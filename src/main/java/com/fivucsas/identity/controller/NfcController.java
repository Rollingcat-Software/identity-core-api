package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.service.ManageNfcCardService;
import com.fivucsas.identity.application.service.ManageNfcCardService.DeactivateOutcome;
import com.fivucsas.identity.application.service.ManageNfcCardService.EnrollResult;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient;
import com.fivucsas.identity.security.CustomUserDetails;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * REST controller for NFC card enrollment.
 *
 * <p>Holds no transaction boundaries of its own — all card mutation,
 * read, and enrollment side-effects happen inside
 * {@link ManageNfcCardService} (P1-Q9, quality review 2026-05-01).</p>
 */
@RestController
@RequestMapping("/api/v1/nfc")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "NFC Card Enrollment", description = "NFC card registration and verification endpoints")
public class NfcController {

    private final ManageNfcCardService manageNfcCardService;
    private final BiometricProcessorClient biometricProcessorClient;
    private final AuditLogPort auditLogPort;

    @PostMapping("/enroll")
    @Operation(summary = "Enroll an NFC card for a user")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> enrollCard(@RequestBody Map<String, String> request) {
        String userIdStr = request.get("userId");
        String cardSerial = request.get("cardSerial");
        String cardType = request.getOrDefault("cardType", "UNKNOWN");
        String label = request.get("label");

        if (cardSerial == null || cardSerial.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "cardSerial is required"
            ));
        }

        UUID requestedUserId = (userIdStr != null && !userIdStr.isBlank())
                ? UUID.fromString(userIdStr)
                : null;

        EnrollResult result = manageNfcCardService.enrollCard(requestedUserId, cardSerial, cardType, label);

        return switch (result.status()) {
            case CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "message", "Card is already enrolled in this tenant"));
            case USER_NOT_FOUND -> ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "User not found"));
            case OK -> ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "success", true,
                    "message", "Card enrolled successfully",
                    "cardId", result.card().getId().toString(),
                    "cardSerial", result.card().getCardSerial(),
                    "userId", result.targetUserId().toString()));
        };
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify an NFC card — returns user info if enrolled")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> verifyCard(@RequestBody Map<String, String> request) {
        String cardSerial = request.get("cardSerial");

        if (cardSerial == null || cardSerial.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "cardSerial is required"
            ));
        }

        Optional<NfcCard> card = manageNfcCardService.verifyCard(cardSerial);

        if (card.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "success", false,
                    "enrolled", false,
                    "message", "Card is not enrolled"
            ));
        }

        NfcCard nfcCard = card.get();
        User user = nfcCard.getUser();

        return ResponseEntity.ok(Map.of(
                "success", true,
                "enrolled", true,
                "userId", user.getId().toString(),
                "userName", user.getFirstName() + " " + user.getLastName(),
                "email", user.getEmail(),
                "cardType", nfcCard.getCardType(),
                "enrolledAt", nfcCard.getEnrolledAt().toString()
        ));
    }

    @GetMapping("/search/{serial}")
    @Operation(summary = "Look up who owns a specific NFC card serial")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> searchCard(@PathVariable String serial) {
        List<NfcCard> cards = manageNfcCardService.searchByCardSerial(serial);

        if (cards.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "found", false,
                    "message", "No enrollment found for this card serial"
            ));
        }

        List<Map<String, Object>> results = new ArrayList<>();
        for (NfcCard card : cards) {
            User user = card.getUser();
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("cardId", card.getId().toString());
            entry.put("userId", user.getId().toString());
            entry.put("userName", user.getFirstName() + " " + user.getLastName());
            entry.put("email", user.getEmail());
            entry.put("cardType", card.getCardType());
            entry.put("isActive", card.isActive());
            entry.put("enrolledAt", card.getEnrolledAt().toString());
            results.add(entry);
        }

        return ResponseEntity.ok(Map.of(
                "found", true,
                "count", cards.size(),
                "results", results
        ));
    }

    @DeleteMapping("/{userId}")
    @Operation(summary = "Remove NFC enrollment for a user")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> removeEnrollment(@PathVariable UUID userId) {
        int deactivated = manageNfcCardService.removeAllUserEnrollments(userId);
        if (deactivated == 0) {
            return ResponseEntity.ok(Map.of(
                    "success", false,
                    "message", "No NFC cards found for this user"
            ));
        }
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "NFC enrollment removed",
                "deactivatedCount", deactivated
        ));
    }

    @GetMapping("/user/{userId}")
    @Operation(summary = "List all NFC cards for a user (active and inactive)")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> listUserCards(@PathVariable UUID userId) {
        List<NfcCard> cards = manageNfcCardService.listUserCards(userId);

        List<Map<String, Object>> results = new ArrayList<>();
        for (NfcCard card : cards) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("cardId", card.getId().toString());
            entry.put("cardSerial", card.getCardSerial());
            entry.put("cardType", card.getCardType());
            entry.put("label", card.getLabel());
            entry.put("isActive", card.isActive());
            entry.put("enrolledAt", card.getEnrolledAt().toString());
            entry.put("lastUsedAt", card.getLastUsedAt() != null ? card.getLastUsedAt().toString() : null);
            results.add(entry);
        }

        return ResponseEntity.ok(Map.of(
                "userId", userId.toString(),
                "count", cards.size(),
                "activeCount", cards.stream().filter(NfcCard::isActive).count(),
                "cards", results
        ));
    }

    @DeleteMapping("/cards/{cardId}")
    @Operation(summary = "Deactivate a specific NFC card by its ID")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> deactivateCard(@PathVariable UUID cardId) {
        DeactivateOutcome outcome = manageNfcCardService.deactivateCard(cardId);
        return switch (outcome) {
            case NOT_FOUND -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                    "success", false,
                    "message", "Card not found or does not belong to you"));
            case ALREADY_INACTIVE -> ResponseEntity.ok(Map.of(
                    "success", false,
                    "message", "Card is already deactivated"));
            case OK -> ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Card deactivated successfully",
                    "cardId", cardId.toString()));
        };
    }

    // ------------------------------------------------------------------
    // T2-A: NFC document MRZ verification via biometric-processor
    // ------------------------------------------------------------------
    // INVESTIGATION_MASTER_2026-05-07.md P1 — wire bio's existing
    // mrz_parser into the NFC auth path. The legacy /verify endpoint
    // above is serial-only and remains unchanged for backward compat;
    // /verify-mrz is the structured-document path used by the hosted
    // login flow when a Web-NFC reader hands us DG1 bytes or a parsed
    // MRZ string from a passport / TR ID card.
    //
    // This endpoint deliberately performs only MRZ parsing + check
    // digit validation. Full ICAO MRTD chip read (DG2 face, BAC/PACE
    // session keys) is a follow-up task — surfacing the parsed
    // identity fields alone already covers ~80% of the NFC-driven
    // KYC use cases at zero crypto risk.

    private static final String BIO_UNAVAILABLE_MARKER = "Biometric processor unavailable";

    @PostMapping("/verify-mrz")
    @Operation(
            summary = "Verify an NFC document MRZ via biometric-processor",
            description = "Parses TD1 (ID card) / TD3 (passport) MRZ and "
                    + "validates ICAO 9303 check digits. Caller must supply "
                    + "exactly one of mrzText or dg1BytesB64."
    )
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> verifyMrz(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {

        String mrzText = trimToNull(request.get("mrzText"));
        String dg1BytesB64 = trimToNull(request.get("dg1BytesB64"));

        if (mrzText == null && dg1BytesB64 == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "errorCode", "NFC_MRZ_MISSING_INPUT",
                    "message", "Provide either mrzText or dg1BytesB64."
            ));
        }
        if (mrzText != null && dg1BytesB64 != null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "errorCode", "NFC_MRZ_AMBIGUOUS_INPUT",
                    "message", "Provide exactly one of mrzText or dg1BytesB64."
            ));
        }

        Map<String, Object> bioResponse =
                biometricProcessorClient.verifyMrz(mrzText, dg1BytesB64);

        // Transport-layer failure path: BiometricProcessorClient surfaces
        // unreachable / 5xx / parse errors as { success=false, error=... }.
        // Distinguish unreachable (502) from rejected (400/422 from bio).
        if (Boolean.FALSE.equals(bioResponse.get("success"))) {
            String err = String.valueOf(bioResponse.getOrDefault("error", ""));
            // Bio rejected the input (HTTP 4xx with detail body) — surface as 400.
            // Bio was reachable but returned 5xx / not reachable at all — 502.
            HttpStatus status = err.startsWith("Biometric processor rejected")
                    ? HttpStatus.BAD_REQUEST
                    : HttpStatus.BAD_GATEWAY;
            String errorCode = err.startsWith("Biometric processor rejected")
                    ? "NFC_MRZ_PARSE_FAILED"
                    : "NFC_MRZ_BIO_UNAVAILABLE";
            log.warn("verifyMrz: biometric-processor failure status={} err={}",
                    status, err);
            return ResponseEntity.status(status).body(Map.of(
                    "success", false,
                    "errorCode", errorCode,
                    "message", err
            ));
        }

        Boolean checksumValid = (Boolean) bioResponse.get("checksum_valid");
        String documentNumber = (String) bioResponse.get("document_number");
        String issuingCountry = (String) bioResponse.get("issuing_country");
        String mrzFormat = (String) bioResponse.get("mrz_format");
        String maskedDocNumber = maskDocumentNumber(documentNumber);

        // Always audit — both success and failure are interesting events.
        try {
            String userId = currentUserId();
            String ipAddress = clientIp(httpRequest);
            String userAgent = httpRequest != null ? httpRequest.getHeader("User-Agent") : null;
            auditLogPort.logNfcDocumentVerified(
                    userId,
                    maskedDocNumber,
                    issuingCountry,
                    mrzFormat,
                    Boolean.TRUE.equals(checksumValid),
                    ipAddress,
                    userAgent
            );
        } catch (Exception auditEx) {
            // Never let an audit-write failure block the auth path.
            log.error("Failed to write NFC verification audit log: {}",
                    auditEx.getMessage(), auditEx);
        }

        if (!Boolean.TRUE.equals(checksumValid)) {
            @SuppressWarnings("unchecked")
            List<String> failures = (List<String>) bioResponse.getOrDefault(
                    "checksum_failures", List.of());
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "errorCode", "NFC_MRZ_CHECKSUM_FAILED",
                    "message", "One or more MRZ check digits failed validation.",
                    "checksumFailures", failures
            ));
        }

        // Happy path — surface the parsed identity fields back to the
        // client. We strip the full document_number from the response
        // and replace it with the masked form so the auth widget can
        // confirm "we read your document ending in 1234" without ever
        // re-exposing the raw value. Callers that need the full number
        // (e.g. enrollment flows that match the document against an
        // existing user record) must use the manual-KYC pipeline.
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("documentType", bioResponse.get("document_type"));
        response.put("issuingCountry", issuingCountry);
        response.put("surname", bioResponse.get("surname"));
        response.put("givenNames", bioResponse.get("given_names"));
        response.put("documentNumberMasked", maskedDocNumber);
        response.put("nationality", bioResponse.get("nationality"));
        response.put("dateOfBirth", bioResponse.get("date_of_birth"));
        response.put("sex", bioResponse.get("sex"));
        response.put("dateOfExpiry", bioResponse.get("date_of_expiry"));
        response.put("mrzFormat", mrzFormat);
        response.put("checksumValid", true);

        return ResponseEntity.ok(response);
    }

    // --- helpers -------------------------------------------------------

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String trimmed = s.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Returns the last 4 characters of the document number. Audit rows
     * and response payloads only ever see this — full document numbers
     * are PII and must not be logged. Returns null/empty inputs as-is.
     */
    static String maskDocumentNumber(String documentNumber) {
        if (documentNumber == null || documentNumber.isBlank()) {
            return documentNumber;
        }
        if (documentNumber.length() <= 4) {
            // Pathologically short — return as-is rather than expose the
            // full value via length-leakage. Short docs are rare enough
            // that this is acceptable.
            return "****";
        }
        int tail = 4;
        String suffix = documentNumber.substring(documentNumber.length() - tail);
        return "*".repeat(documentNumber.length() - tail) + suffix;
    }

    private static String currentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof CustomUserDetails cud)) {
            return null;
        }
        return cud.getUserId() != null ? cud.getUserId().toString() : null;
    }

    private static String clientIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
