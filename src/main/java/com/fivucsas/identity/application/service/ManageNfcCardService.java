package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.model.NfcSerial;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
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
    private final TenantScopeResolver tenantScopeResolver;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

    /**
     * Outcome of an enroll attempt. {@link Status#OK} carries the saved card;
     * the rejection statuses carry no payload and are mapped to HTTP status by
     * the controller.
     *
     * <p>P1-8: {@link Status#CARD_REVOKED} and {@link Status#OWNED_BY_ANOTHER_USER}
     * fail-close the two silent re-enroll transitions that re-enrolling a card
     * previously triggered — auto-reactivating an administratively revoked card,
     * and silently re-pointing a card to a different owner. Both require an
     * explicit re-authorization (the {@code reauthorize} flag) rather than
     * happening as an invisible side-effect of a tap.</p>
     */
    public record EnrollResult(Status status, NfcCard card, UUID targetUserId) {
        public enum Status { OK, CONFLICT, USER_NOT_FOUND, CARD_REVOKED, OWNED_BY_ANOTHER_USER }
    }

    @Transactional
    public EnrollResult enrollCard(UUID requestedUserId, String rawCardSerial,
                                   String cardType, String label) {
        return enrollCard(requestedUserId, rawCardSerial, cardType, label, false);
    }

    /**
     * Enroll (or re-enroll) an NFC card.
     *
     * @param reauthorize when {@code true}, the caller has EXPLICITLY
     *        re-authorized the two otherwise-refused re-enroll transitions:
     *        reactivating a previously revoked card, and reassigning a card to a
     *        different owner. When {@code false} (the default), those transitions
     *        are rejected ({@link EnrollResult.Status#CARD_REVOKED} /
     *        {@link EnrollResult.Status#OWNED_BY_ANOTHER_USER}) so they never
     *        happen as a silent side-effect of a tap (P1-8). A benign re-enroll
     *        of the SAME owner's still-active card is unaffected.
     */
    @Transactional
    public EnrollResult enrollCard(UUID requestedUserId, String rawCardSerial,
                                   String cardType, String label, boolean reauthorize) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);
        Tenant tenant = currentUser.getTenant();

        // Normalize the serial to the canonical UPPERHEX form at ingest so a
        // card enrolled from mobile (UPPERHEX) matches one verified from web
        // (lowercase:colons) and vice-versa. Stored value is always canonical.
        String cardSerial = NfcSerial.canonicalize(rawCardSerial);

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

            // P1-8 — fail-closed guards against silent privilege transitions on
            // re-enroll. Both are bypassable ONLY with an explicit reauthorize=true.
            //
            // (1) A card that was deliberately REVOKED (deactivate() flips
            //     isActive=false AND stamps revokedAt — e.g. a lost/stolen card an
            //     admin deactivated) must NOT be auto-promoted back to active by a
            //     re-tap. Reactivating a revoked credential is a security decision,
            //     not an implicit consequence of presenting the card.
            boolean isRevoked = !existing.isActive() && existing.getRevokedAt() != null;
            if (isRevoked && !reauthorize) {
                log.warn("AUDIT: NFC re-enroll refused — card revoked, explicit re-authorization required: "
                        + "serial={} tenant={} requestedBy={}", cardSerial, tenant.getId(), currentUser.getId());
                return new EnrollResult(EnrollResult.Status.CARD_REVOKED, null, targetUserId);
            }

            // (2) A card currently owned by a DIFFERENT user must NOT be silently
            //     re-pointed to the target user. Ownership reassignment is a
            //     deliberate administrative action, never a side-effect of enroll.
            UUID existingOwnerId = existing.getUser() != null ? existing.getUser().getId() : null;
            boolean differentOwner = existingOwnerId != null && !existingOwnerId.equals(targetUserId);
            if (differentOwner && !reauthorize) {
                log.warn("AUDIT: NFC re-enroll refused — card owned by another user, explicit re-authorization "
                        + "required: serial={} tenant={} currentOwner={} requestedTarget={} requestedBy={}",
                        cardSerial, tenant.getId(), existingOwnerId, targetUserId, currentUser.getId());
                return new EnrollResult(EnrollResult.Status.OWNED_BY_ANOTHER_USER, null, targetUserId);
            }

            existing.activate();
            existing.setUser(targetUser);
            existing.setCardType(cardType);
            if (label != null) existing.setLabel(label);
            existing.setEnrolledAt(Instant.now());
            saved = nfcCardRepository.save(existing);
            log.info("NFC card reactivated: serial={} user={} tenant={} reauthorized={}",
                    cardSerial, targetUserId, tenant.getId(), reauthorize);
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
    public Optional<NfcCard> verifyCard(String rawCardSerial) {
        // Same canonicalization as enroll so cross-client (web ↔ mobile) serial
        // shapes resolve to the same stored value.
        return nfcCardRepository.findByCardSerialAndIsActiveTrue(NfcSerial.canonicalize(rawCardSerial));
    }

    /**
     * Looks up enrollments for a card serial, scoped to the caller's tenant.
     *
     * <p>S11 (security review): the previous implementation called
     * {@code findByCardSerial} with no tenant filter, so any authenticated
     * user could discover who owns a card serial in <em>any</em> tenant —
     * a cross-tenant PII leak. This now restricts the result set to the
     * caller's own tenant. ROOT (no tenant attached, cross-tenant by design)
     * retains the unscoped global view used by platform operators.</p>
     *
     * <p>The {@code @PreAuthorize} on the controller endpoint additionally
     * requires the {@code device:read} admin permission, so an ordinary
     * tenant member cannot reach this lookup at all.</p>
     */
    @Transactional(readOnly = true)
    public List<NfcCard> searchByCardSerial(String rawSerial) {
        // Canonicalize so an admin can search with either client's serial shape.
        String serial = NfcSerial.canonicalize(rawSerial);
        // Resolve the caller's tenant scope via the security layer rather than
        // entity.User, so this application service stays within the hexagonal
        // boundary (UserDomainBoundaryTest). ROOT has an
        // unrestricted scope and keeps the unscoped global view used by
        // platform operators; everyone else is confined to their own tenant
        // (a non-super-admin with no resolvable tenant gets the fail-closed
        // empty scope, which the scoped query returns no rows for).
        if (tenantScopeResolver.isUnrestricted()) {
            return nfcCardRepository.findByCardSerial(serial);
        }
        return nfcCardRepository.findAllByCardSerialAndTenantId(serial, tenantScopeResolver.currentScope());
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
