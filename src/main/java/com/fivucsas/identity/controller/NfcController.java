package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.ManageNfcCardService;
import com.fivucsas.identity.application.service.ManageNfcCardService.DeactivateOutcome;
import com.fivucsas.identity.application.service.ManageNfcCardService.EnrollResult;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
}
