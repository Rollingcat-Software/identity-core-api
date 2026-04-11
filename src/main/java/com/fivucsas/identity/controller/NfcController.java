package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import java.util.List;
import java.util.Optional;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
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

    private final NfcCardRepositoryPort nfcCardRepository;
    private final UserRepository userRepository;
    private final RbacAuthorizationService rbacService;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

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

        // Check if card is already actively enrolled in this tenant
        if (nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue(cardSerial, tenant.getId())) {
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

        // Check for existing inactive card (previously revoked) — reactivate instead of creating new
        Optional<NfcCard> existingCard = nfcCardRepository.findByCardSerialAndTenantId(cardSerial, tenant.getId());
        NfcCard saved;
        if (existingCard.isPresent()) {
            NfcCard existing = existingCard.get();
            existing.activate();
            existing.setUser(targetUser);
            existing.setCardType(cardType);
            if (label != null) existing.setLabel(label);
            existing.setEnrolledAt(java.time.Instant.now());
            saved = nfcCardRepository.save(existing);
            log.info("NFC card reactivated: serial={} user={} tenant={}", cardSerial, targetUserId, tenant.getId());
        } else {
            NfcCard card = NfcCard.builder()
                    .user(targetUser)
                    .tenant(tenant)
                    .cardSerial(cardSerial)
                    .cardType(cardType)
                    .label(label)
                    .build();
            saved = nfcCardRepository.save(card);
            log.info("NFC card enrolled: serial={} user={} tenant={}", cardSerial, targetUserId, tenant.getId());
        }
        log.info("NFC card enrolled: serial={} user={} tenant={}", cardSerial, targetUserId, tenant.getId());

        // Auto-create + auto-complete the enrollment record so the enrollment page
        // shows NFC_DOCUMENT as ENROLLED. NFC_DOCUMENT is in AUTO_COMPLETE_TYPES,
        // so startEnrollment() will immediately mark it as ENROLLED.
        try {
            manageEnrollmentUseCase.startEnrollment(targetUserId, tenant.getId(), AuthMethodType.NFC_DOCUMENT);
            log.info("Auto-completed NFC_DOCUMENT enrollment for user {}", targetUserId);
        } catch (Exception e) {
            log.warn("Failed to auto-complete NFC_DOCUMENT enrollment for user {} after card registration: {}",
                    targetUserId, e.getMessage());
        }

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
    @Operation(summary = "List all NFC cards for a user (active and inactive)")
    @PreAuthorize("isAuthenticated()")
    @Transactional(readOnly = true)
    public ResponseEntity<Map<String, Object>> listUserCards(@PathVariable UUID userId) {
        List<NfcCard> cards = nfcCardRepository.findByUserId(userId);

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
    @Transactional
    public ResponseEntity<Map<String, Object>> deactivateCard(@PathVariable UUID cardId) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);

        // Find the card — use findByUserId and filter, since we don't have findById on port
        List<NfcCard> userCards = nfcCardRepository.findByUserId(currentUser.getId());
        Optional<NfcCard> targetCard = userCards.stream()
                .filter(c -> c.getId().equals(cardId))
                .findFirst();

        if (targetCard.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                    "success", false,
                    "message", "Card not found or does not belong to you"
            ));
        }

        NfcCard card = targetCard.get();
        if (!card.isActive()) {
            return ResponseEntity.ok(Map.of(
                    "success", false,
                    "message", "Card is already deactivated"
            ));
        }

        card.deactivate();
        nfcCardRepository.save(card);
        log.info("NFC card {} deactivated by user {}", cardId, currentUser.getId());

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Card deactivated successfully",
                "cardId", cardId.toString()
        ));
    }
}
