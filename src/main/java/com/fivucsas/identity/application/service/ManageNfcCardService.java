package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * NFC card enrollment / verification / lookup application service.
 *
 * <p>Holds the transaction boundary for all NFC card operations. The
 * controller ({@code NfcController}) is responsible only for HTTP shape;
 * persistence and side-effects (auto-completion of NFC enrollment record)
 * happen here.</p>
 *
 * <p>Quality batch P1-Q9 (review 2026-05-01): moved out of
 * {@code NfcController} per the "no @Transactional on controllers" rule.
 * Behaviour is intentionally byte-for-byte preserved against the previous
 * controller-resident implementation; only the transaction boundary
 * relocates.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageNfcCardService {

    private final NfcCardRepositoryPort nfcCardRepository;
    private final UserRepository userRepository;
    private final RbacAuthorizationService rbacService;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

    /**
     * Outcome of an enroll attempt. {@link Status#OK} carries the saved card;
     * {@link Status#CONFLICT}/{@link Status#USER_NOT_FOUND} carry no payload
     * and are mapped to HTTP status by the controller.
     */
    public record EnrollResult(Status status, NfcCard card, UUID targetUserId) {
        public enum Status { OK, CONFLICT, USER_NOT_FOUND }
    }

    @Transactional
    public EnrollResult enrollCard(UUID requestedUserId, String cardSerial,
                                   String cardType, String label) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);
        Tenant tenant = currentUser.getTenant();

        UUID targetUserId = requestedUserId != null ? requestedUserId : currentUser.getId();

        if (nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue(cardSerial, tenant.getId())) {
            return new EnrollResult(EnrollResult.Status.CONFLICT, null, targetUserId);
        }

        User targetUser = userRepository.findById(targetUserId).orElse(null);
        if (targetUser == null) {
            return new EnrollResult(EnrollResult.Status.USER_NOT_FOUND, null, targetUserId);
        }

        Optional<NfcCard> existingCard = nfcCardRepository.findByCardSerialAndTenantId(cardSerial, tenant.getId());
        NfcCard saved;
        if (existingCard.isPresent()) {
            NfcCard existing = existingCard.get();
            existing.activate();
            existing.setUser(targetUser);
            existing.setCardType(cardType);
            if (label != null) existing.setLabel(label);
            existing.setEnrolledAt(Instant.now());
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

        // Auto-create + auto-complete the enrollment record (NFC_DOCUMENT is in
        // AUTO_COMPLETE_TYPES so startEnrollment marks it ENROLLED immediately).
        try {
            manageEnrollmentUseCase.startEnrollment(targetUserId, tenant.getId(), AuthMethodType.NFC_DOCUMENT);
            log.info("Auto-completed NFC_DOCUMENT enrollment for user {}", targetUserId);
        } catch (Exception e) {
            log.warn("Failed to auto-complete NFC_DOCUMENT enrollment for user {} after card registration: {}",
                    targetUserId, e.getMessage());
        }

        return new EnrollResult(EnrollResult.Status.OK, saved, targetUserId);
    }

    @Transactional(readOnly = true)
    public Optional<NfcCard> verifyCard(String cardSerial) {
        return nfcCardRepository.findByCardSerialAndIsActiveTrue(cardSerial);
    }

    @Transactional(readOnly = true)
    public List<NfcCard> searchByCardSerial(String serial) {
        return nfcCardRepository.findByCardSerial(serial);
    }

    /**
     * Deactivates every active NFC card for a user. Returns the deactivated count
     * (0 if no cards were found at all).
     */
    @Transactional
    public int removeAllUserEnrollments(UUID userId) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);

        List<NfcCard> cards = nfcCardRepository.findByUserId(userId);
        if (cards.isEmpty()) {
            return 0;
        }
        for (NfcCard card : cards) {
            card.deactivate();
        }
        nfcCardRepository.saveAll(cards);
        log.info("NFC cards deactivated for user={} by={}", userId, currentUser.getId());
        return cards.size();
    }

    @Transactional(readOnly = true)
    public List<NfcCard> listUserCards(UUID userId) {
        return nfcCardRepository.findByUserId(userId);
    }

    public enum DeactivateOutcome { OK, NOT_FOUND, ALREADY_INACTIVE }

    /**
     * Deactivates a specific NFC card by id, scoped to the current authenticated
     * user (a user may not deactivate someone else's card).
     */
    @Transactional
    public DeactivateOutcome deactivateCard(UUID cardId) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);

        List<NfcCard> userCards = nfcCardRepository.findByUserId(currentUser.getId());
        Optional<NfcCard> targetCard = userCards.stream()
                .filter(c -> c.getId().equals(cardId))
                .findFirst();

        if (targetCard.isEmpty()) {
            return DeactivateOutcome.NOT_FOUND;
        }

        NfcCard card = targetCard.get();
        if (!card.isActive()) {
            return DeactivateOutcome.ALREADY_INACTIVE;
        }

        card.deactivate();
        nfcCardRepository.save(card);
        log.info("NFC card {} deactivated by user {}", cardId, currentUser.getId());
        return DeactivateOutcome.OK;
    }
}
