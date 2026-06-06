package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ManageNfcCardService;
import com.fivucsas.identity.application.service.nfc.NfcChipAuthenticityVerdict;
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
    private final BiometricServicePort biometricServicePort;
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

        // WS2: if the client read the chip's EF.SOD, gate enrollment on the
        // authoritative passive-auth (chip-authenticity) verdict — a cloned or
        // emulated card must not be enrollable. Fail-closed. When no SOD is
        // supplied (serial-only legacy/basic enroll), behaviour is unchanged.
        String sod = trimToNull(request.get("sod"));
        if (sod == null) {
            sod = trimToNull(request.get("sod_b64"));
        }
        if (sod != null) {
            NfcChipAuthenticityVerdict verdict = NfcChipAuthenticityVerdict.from(
                    biometricServicePort.verifyNfcChipAuthenticity(sod, extractDataGroups(request)));
            if (!verdict.isAuthentic()) {
                log.warn("NFC enroll rejected — chip not authentic: code={} reason={}",
                        verdict.reasonCode(), verdict.reason());
                Map<String, Object> rejected = new LinkedHashMap<>();
                rejected.put("success", false);
                rejected.put("errorCode", "NFC_PA_NOT_AUTHENTIC");
                if (verdict.reasonCode() != null) {
                    rejected.put("reasonCode", verdict.reasonCode());
                }
                rejected.put("message", verdict.reason() != null
                        ? verdict.reason()
                        : "Chip passive authentication failed; card not enrolled.");
                return ResponseEntity.unprocessableEntity().body(rejected);
            }
        }

        UUID requestedUserId = (userIdStr != null && !userIdStr.isBlank())
                ? UUID.fromString(userIdStr)
                : null;

        // P1-8: explicit re-authorization for the two otherwise-refused re-enroll
        // transitions (reactivate a revoked card / reassign ownership). Absent or
        // any non-"true" value keeps the safe default (false).
        boolean reauthorize = "true".equalsIgnoreCase(trimToNull(request.get("reauthorize")));

        // OPTIONAL stable eID/passport DG1 document number (e.g. "A28883159"), read
        // during a BAC chip read. When present the service keys the card identity on
        // the document number instead of the random NFC UID, so a re-read of the same
        // eID (a DIFFERENT random UID per tap) reactivates/updates the existing row
        // rather than inserting a duplicate. Omitted for plain MIFARE UID cards →
        // unchanged legacy UID-based de-dup (backward compatible).
        String documentNumber = trimToNull(request.get("documentNumber"));

        EnrollResult result = manageNfcCardService.enrollCard(
                requestedUserId, cardSerial, cardType, label, reauthorize, documentNumber);

        return switch (result.status()) {
            case CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "message", "Card is already enrolled in this tenant"));
            case CARD_REVOKED -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "errorCode", "NFC_CARD_REVOKED",
                    "message", "This card was revoked. Re-enrolling it requires explicit "
                            + "re-authorization (set reauthorize=true)."));
            case OWNED_BY_ANOTHER_USER -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "errorCode", "NFC_CARD_OWNED_BY_ANOTHER_USER",
                    "message", "This card is enrolled to a different user. Reassigning it requires "
                            + "explicit re-authorization (set reauthorize=true)."));
            case USER_NOT_FOUND -> ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "User not found"));
            case OK -> ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "success", true,
                    // alreadyRegistered=true → the card/document already existed and was
                    // reactivated/updated (the contract signal the mobile result screen
                    // reads to show "Already registered" / "Card recognized"); false → a
                    // brand-new enrollment ("Registered successfully").
                    "alreadyRegistered", result.alreadyRegistered(),
                    "message", result.alreadyRegistered()
                            ? "Card already registered — reactivated"
                            : "Card enrolled successfully",
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
    @Operation(summary = "Look up who owns a specific NFC card serial (admin, tenant-scoped)")
    // S11 (security review): this lookup exposes who owns a card serial — PII.
    // Previously gated only by isAuthenticated(), so any logged-in user could
    // enumerate card owners across every tenant. Require the device:read admin
    // permission (an NFC card is a physical credential/device); the service
    // additionally restricts results to the caller's own tenant (ROOT excepted).
    @PreAuthorize("@rbac.hasPermission('device:read')")
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

    // ------------------------------------------------------------------
    // WS2: NFC chip passive-authentication (SOD → DS → CSCA) trust check
    // ------------------------------------------------------------------
    // The serial-only /verify path proves "this serial is enrolled" but NOT
    // that the physical chip is genuine — a cloned/emulated card can present
    // any serial. Passive Authentication validates the eMRTD EF.SOD signature
    // chain (Document Signer → CSCA) and that the read Data Group hashes match
    // those signed in the SOD. The biometric-processor performs the crypto
    // (CPU-only, X-API-Key); the api treats the result as AUTHORITATIVE and is
    // FAIL-CLOSED: any error or non-authentic verdict rejects the chip.
    //
    // Clients (web Web-NFC, mobile CoreNFC/Android) run an advisory local check
    // but MUST send SOD + DGs here for the trusted verdict before relying on an
    // NFC enroll/verify.

    @PostMapping("/verify-authenticity")
    @Operation(
            summary = "Verify NFC chip authenticity (passive authentication)",
            description = "Validates the eMRTD EF.SOD → Document Signer → CSCA "
                    + "certificate chain and the DG-hash binding via the "
                    + "biometric-processor. Fail-closed: a non-authentic verdict "
                    + "or any service error rejects the chip. Send the base64 "
                    + "EF.SOD as 'sod' (or 'sod_b64') and any read data groups as "
                    + "dg1..dgN (or numeric keys 1..N)."
    )
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> verifyChipAuthenticity(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {

        // Accept either 'sod' or the bio-native 'sod_b64' from clients.
        String sod = trimToNull(request.get("sod"));
        if (sod == null) {
            sod = trimToNull(request.get("sod_b64"));
        }
        if (sod == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "authentic", false,
                    "errorCode", "NFC_PA_MISSING_SOD",
                    "message", "The base64-encoded EF.SOD ('sod') is required."
            ));
        }

        Map<String, String> dataGroups = extractDataGroups(request);

        Map<String, Object> bioResponse =
                biometricServicePort.verifyNfcChipAuthenticity(sod, dataGroups);
        NfcChipAuthenticityVerdict verdict = NfcChipAuthenticityVerdict.from(bioResponse);

        // Audit both authentic and rejected outcomes.
        try {
            String userId = currentUserId();
            String ipAddress = clientIp(httpRequest);
            String userAgent = httpRequest != null ? httpRequest.getHeader("User-Agent") : null;
            auditLogPort.logSecurityEvent(
                    userId,
                    verdict.isAuthentic() ? "NFC_CHIP_AUTHENTIC" : "NFC_CHIP_NOT_AUTHENTIC",
                    ipAddress,
                    String.format("NFC passive-auth verdict=%s reason=%s ua=%s dgs=%d",
                            verdict.isAuthentic(), verdict.reason(), userAgent, dataGroups.size())
            );
        } catch (Exception auditEx) {
            log.error("Failed to write NFC chip-authenticity audit log: {}",
                    auditEx.getMessage(), auditEx);
        }

        if (!verdict.isAuthentic()) {
            // Fail-closed. 422 = reachable-but-rejected (chip not authentic),
            // distinct from a transport problem which the verdict folds in too;
            // we keep a single 422 so a cloned chip can't be told apart from a
            // service blip by an attacker probing the endpoint.
            log.warn("NFC chip rejected as not authentic: code={} reason={}",
                    verdict.reasonCode(), verdict.reason());
            Map<String, Object> rejected = new LinkedHashMap<>();
            rejected.put("success", false);
            rejected.put("authentic", false);
            rejected.put("errorCode", "NFC_PA_NOT_AUTHENTIC");
            if (verdict.reasonCode() != null) {
                rejected.put("reasonCode", verdict.reasonCode());
            }
            rejected.put("message", verdict.reason() != null
                    ? verdict.reason()
                    : "Chip passive authentication failed.");
            return ResponseEntity.unprocessableEntity().body(rejected);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("authentic", true);
        if (verdict.reasonCode() != null) {
            response.put("reasonCode", verdict.reasonCode());
        }
        if (verdict.reason() != null) {
            response.put("detail", verdict.reason());
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Collects data-group base64 values from a request map. Accepts both the
     * bio-native numeric keys ("1", "2", "14") and dg-prefixed keys ("dg1",
     * "dg2"); the adapter normalizes to the numeric form. Non-DG keys (sod,
     * sod_b64, cardSerial, etc.) are ignored.
     */
    private static Map<String, String> extractDataGroups(Map<String, String> request) {
        Map<String, String> dataGroups = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : request.entrySet()) {
            String key = e.getKey() == null ? "" : e.getKey().toLowerCase().trim();
            if (e.getValue() == null || e.getValue().isBlank()) {
                continue;
            }
            // dg1..dgN
            if (key.matches("dg\\d{1,2}")) {
                dataGroups.put(key, e.getValue().trim());
            } else if (key.matches("\\d{1,2}")) {
                // bare numeric DG key
                dataGroups.put("dg" + key, e.getValue().trim());
            }
        }
        return dataGroups;
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
