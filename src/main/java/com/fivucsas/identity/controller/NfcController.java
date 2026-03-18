package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.NfcCardRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/nfc")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "NFC Card Enrollment", description = "NFC card registration and verification endpoints")
public class NfcController {

    private final NfcCardRepository nfcCardRepository;
    private final UserRepository userRepository;
    private final RbacAuthorizationService rbacService;

    @PostMapping("/enroll")
    @Operation(summary = "Enroll an NFC card for a user")
    @PreAuthorize("isAuthenticated()")
    @Transactional
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

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);
        Tenant tenant = currentUser.getTenant();

        // Determine target user
        UUID targetUserId;
        if (userIdStr != null && !userIdStr.isBlank()) {
            targetUserId = UUID.fromString(userIdStr);
        } else {
            targetUserId = currentUser.getId();
        }

        // Check if card is already enrolled in this tenant
        if (nfcCardRepository.existsByCardSerialAndTenantId(cardSerial, tenant.getId())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "success", false,
                    "message", "Card is already enrolled in this tenant"
            ));
        }

        // Find target user
        User targetUser = userRepository.findById(targetUserId).orElse(null);
        if (targetUser == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "User not found"
            ));
        }

        NfcCard card = NfcCard.builder()
                .user(targetUser)
                .tenant(tenant)
                .cardSerial(cardSerial)
                .cardType(cardType)
                .label(label)
                .build();

        NfcCard saved = nfcCardRepository.save(card);
        log.info("NFC card enrolled: serial={} user={} tenant={}", cardSerial, targetUserId, tenant.getId());

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "success", true,
                "message", "Card enrolled successfully",
                "cardId", saved.getId().toString(),
                "cardSerial", saved.getCardSerial(),
                "userId", targetUserId.toString()
        ));
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify an NFC card — returns user info if enrolled")
    @PreAuthorize("isAuthenticated()")
    @Transactional(readOnly = true)
    public ResponseEntity<Map<String, Object>> verifyCard(@RequestBody Map<String, String> request) {
        String cardSerial = request.get("cardSerial");

        if (cardSerial == null || cardSerial.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "cardSerial is required"
            ));
        }

        Optional<NfcCard> card = nfcCardRepository.findByCardSerialAndIsActiveTrue(cardSerial);

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
    @Transactional(readOnly = true)
    public ResponseEntity<Map<String, Object>> searchCard(@PathVariable String serial) {
        List<NfcCard> cards = nfcCardRepository.findByCardSerial(serial);

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
    @Transactional
    public ResponseEntity<Map<String, Object>> removeEnrollment(@PathVariable UUID userId) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);

        List<NfcCard> cards = nfcCardRepository.findByUserId(userId);
        if (cards.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "success", false,
                    "message", "No NFC cards found for this user"
            ));
        }

        // Deactivate all cards for the user
        for (NfcCard card : cards) {
            card.deactivate();
        }
        nfcCardRepository.saveAll(cards);

        log.info("NFC cards deactivated for user={} by={}", userId, currentUser.getId());

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "NFC enrollment removed",
                "deactivatedCount", cards.size()
        ));
    }

    @GetMapping("/user/{userId}")
    @Operation(summary = "List all NFC cards for a user")
    @PreAuthorize("isAuthenticated()")
    @Transactional(readOnly = true)
    public ResponseEntity<Map<String, Object>> listUserCards(@PathVariable UUID userId) {
        List<NfcCard> cards = nfcCardRepository.findByUserIdAndIsActiveTrue(userId);

        List<Map<String, Object>> results = new ArrayList<>();
        for (NfcCard card : cards) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("cardId", card.getId().toString());
            entry.put("cardSerial", card.getCardSerial());
            entry.put("cardType", card.getCardType());
            entry.put("label", card.getLabel());
            entry.put("enrolledAt", card.getEnrolledAt().toString());
            entry.put("lastUsedAt", card.getLastUsedAt() != null ? card.getLastUsedAt().toString() : null);
            results.add(entry);
        }

        return ResponseEntity.ok(Map.of(
                "userId", userId.toString(),
                "count", cards.size(),
                "cards", results
        ));
    }
}
