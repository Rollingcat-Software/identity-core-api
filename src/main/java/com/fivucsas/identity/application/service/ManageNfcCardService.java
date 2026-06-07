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

    /**
     * Admin permission gating NFC operations on behalf of another user. An NFC
     * card is a physical credential/device, so it reuses the existing
     * {@code device:create} admin permission (the same family as the
     * {@code device:read} gate already on {@code /search/{serial}}). Holding it
     * lets a tenant admin enroll/remove cards for users they manage; without it
     * a caller may only act on their OWN cards.
     */
    private static final String NFC_ADMIN_PERMISSION = "device:create";

    /**
     * Read permission gating NFC PII reads on behalf of another user (the same
     * {@code device:read} gate already on {@code /search/{serial}}).
     */
    private static final String NFC_READ_PERMISSION = "device:read";

    private final NfcCardRepositoryPort nfcCardRepository;
    private final UserRepository userRepository;
    private final RbacAuthorizationService rbacService;
    private final TenantScopeResolver tenantScopeResolver;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

    /**
     * Verifies that the {@code targetUserId} resolves to a user whose tenant the
     * caller is allowed to manage. Mirrors the {@code TenantScopeResolver}
     * pattern used by the listing endpoints: ROOT may act cross-tenant; a
     * tenant-bound admin may act only inside their own tenant scope. A target
     * with no resolvable tenant, or in a tenant outside the caller's scope, is
     * refused with 403 (we deliberately do NOT distinguish "no such user" from
     * "other tenant" to avoid a cross-tenant user-enumeration oracle).
     */
    private void assertTargetWithinManageableTenant(UUID targetUserId, User caller) {
        UUID targetTenantId = userRepository.findById(targetUserId)
                .map(User::getTenant)
                .map(Tenant::getId)
                .orElse(null);
        if (targetTenantId == null || !tenantScopeResolver.canAccessTenant(targetTenantId)) {
            log.warn("AUDIT: NFC admin action refused — caller {} may not manage target {} (targetTenant={})",
                    caller.getId(), targetUserId, targetTenantId);
            throw new UnauthorizedException(
                    "You may only manage NFC cards for users within a tenant you administer");
        }
    }

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
    public record EnrollResult(Status status, NfcCard card, UUID targetUserId, boolean alreadyRegistered) {
        public enum Status { OK, CONFLICT, USER_NOT_FOUND, CARD_REVOKED, OWNED_BY_ANOTHER_USER }

        /** Rejection statuses carry no card and were never "already registered". */
        static EnrollResult rejection(Status status, UUID targetUserId) {
            return new EnrollResult(status, null, targetUserId, false);
        }
    }

    @Transactional
    public EnrollResult enrollCard(UUID requestedUserId, String rawCardSerial,
                                   String cardType, String label) {
        return enrollCard(requestedUserId, rawCardSerial, cardType, label, false, null);
    }

    @Transactional
    public EnrollResult enrollCard(UUID requestedUserId, String rawCardSerial,
                                   String cardType, String label, boolean reauthorize) {
        return enrollCard(requestedUserId, rawCardSerial, cardType, label, reauthorize, null);
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
     * @param documentNumber OPTIONAL stable eID/passport DG1 document number
     *        (e.g. "A28883159"), read during a BAC chip read. When present it is
     *        the STABLE identity of the card and is used as the canonical card
     *        serial INSTEAD of the random NFC UID — an eID presents a DIFFERENT
     *        random UID on every tap, so keying on the document number lets a
     *        re-read UPDATE/REACTIVATE the existing row rather than inserting a
     *        duplicate. {@code nfc_cards} has no separate document-number column,
     *        so the document number IS the stored card_serial and the existing
     *        serial-based de-dup naturally collapses the re-reads. When ABSENT
     *        (plain MIFARE UID cards), behaviour is byte-for-byte the legacy
     *        UID/serial-based de-dup.
     */
    @Transactional
    public EnrollResult enrollCard(UUID requestedUserId, String rawCardSerial,
                                   String cardType, String label, boolean reauthorize,
                                   String documentNumber) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);
        Tenant tenant = currentUser.getTenant();

        // SECURITY (authz IDOR fix, 2026-06-07): the enroll endpoint is
        // isAuthenticated()-only and takes the target userId from the request
        // body. Without a guard, any authenticated user could enroll (or, via
        // reauthorize, REASSIGN/REACTIVATE) a card for ANY user in ANY tenant —
        // a critical IDOR. Enforce, in the service (the @PreAuthorize SpEL layer
        // cannot do object-level authz here):
        //   * self-enroll is always allowed (target == caller); OR
        //   * an admin holding device:create may enroll on behalf of another
        //     user, but only WITHIN a tenant the caller may manage; AND
        //   * the privileged reauthorize path (reactivate-revoked / reassign-
        //     owner) ALWAYS requires the device:create admin permission — it can
        //     never be driven by the body flag alone.
        UUID requestedTargetUserId = requestedUserId != null ? requestedUserId : currentUser.getId();
        boolean selfEnroll = requestedTargetUserId.equals(currentUser.getId());
        boolean hasDeviceAdmin = rbacService.hasPermission(NFC_ADMIN_PERMISSION);

        if (reauthorize && !hasDeviceAdmin) {
            log.warn("AUDIT: NFC enroll re-authorization refused — caller {} lacks {} (target={})",
                    currentUser.getId(), NFC_ADMIN_PERMISSION, requestedTargetUserId);
            throw new UnauthorizedException(
                    "Reactivating a revoked card or reassigning ownership requires an admin permission");
        }
        if (!selfEnroll) {
            if (!hasDeviceAdmin) {
                log.warn("AUDIT: NFC enroll refused — non-owner caller {} lacks {} for target {}",
                        currentUser.getId(), NFC_ADMIN_PERMISSION, requestedTargetUserId);
                throw new UnauthorizedException(
                        "You may only enroll an NFC card for yourself unless you are an administrator");
            }
            assertTargetWithinManageableTenant(requestedTargetUserId, currentUser);
        }

        // De-dup key selection (NFC eID random-UID fix):
        //   * documentNumber PRESENT (eID/passport BAC read) → the document number
        //     is the STABLE card identity. Canonicalize THAT and store it as the
        //     card_serial so a re-read (which presents a fresh random UID) resolves
        //     to the SAME row and reactivates/updates it instead of inserting a
        //     duplicate.
        //   * documentNumber ABSENT (plain MIFARE UID card) → legacy behaviour:
        //     canonicalize the raw UID/serial and de-dup on it.
        // Stored value is always the canonical form so cross-client (web ↔ mobile)
        // shapes resolve to one row.
        String dedupSource = (documentNumber != null && !documentNumber.isBlank())
                ? documentNumber
                : rawCardSerial;
        String cardSerial = NfcSerial.canonicalize(dedupSource);

        UUID targetUserId = requestedUserId != null ? requestedUserId : currentUser.getId();

        if (nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue(cardSerial, tenant.getId())) {
            return EnrollResult.rejection(EnrollResult.Status.CONFLICT, targetUserId);
        }

        User targetUser = userRepository.findById(targetUserId).orElse(null);
        if (targetUser == null) {
            return EnrollResult.rejection(EnrollResult.Status.USER_NOT_FOUND, targetUserId);
        }

        Optional<NfcCard> existingCard = nfcCardRepository.findByCardSerialAndTenantId(cardSerial, tenant.getId());
        boolean alreadyRegistered = existingCard.isPresent();
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
                return EnrollResult.rejection(EnrollResult.Status.CARD_REVOKED, targetUserId);
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
                return EnrollResult.rejection(EnrollResult.Status.OWNED_BY_ANOTHER_USER, targetUserId);
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

        return new EnrollResult(EnrollResult.Status.OK, saved, targetUserId, alreadyRegistered);
    }

    @Transactional(readOnly = true)
    public Optional<NfcCard> verifyCard(String rawCardSerial) {
        // SECURITY (authz PII-leak fix, 2026-06-07): /verify returns the owner's
        // name + email. The controller now gates on device:read (mirroring
        // /search/{serial}); here we additionally tenant-scope the result so a
        // tenant-bound admin cannot resolve a card enrolled in another tenant.
        // ROOT (unrestricted) keeps the global view used by platform operators.
        String serial = NfcSerial.canonicalize(rawCardSerial);
        if (tenantScopeResolver.isUnrestricted()) {
            return nfcCardRepository.findByCardSerialAndIsActiveTrue(serial);
        }
        return nfcCardRepository.findByCardSerialAndIsActiveTrue(serial)
                .filter(card -> card.getTenant() != null
                        && tenantScopeResolver.currentScope().equals(card.getTenant().getId()));
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

        // SECURITY (authz IDOR fix, 2026-06-07): DELETE /api/v1/nfc/{userId} was
        // isAuthenticated()-only with no ownership/tenant check, so any user
        // could mass-deactivate ANOTHER user's NFC cards (a self-service DoS /
        // account-takeover lever). Restrict to self, or an admin acting within a
        // tenant they manage — mirrors the enroll guard above.
        if (!userId.equals(currentUser.getId())) {
            if (!rbacService.hasPermission(NFC_ADMIN_PERMISSION)) {
                log.warn("AUDIT: NFC removal refused — non-owner caller {} lacks {} for target {}",
                        currentUser.getId(), NFC_ADMIN_PERMISSION, userId);
                throw new UnauthorizedException(
                        "You may only remove your own NFC cards unless you are an administrator");
            }
            assertTargetWithinManageableTenant(userId, currentUser);
        }

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
        // SECURITY (authz PII-leak fix, 2026-06-07): GET /api/v1/nfc/user/{userId}
        // returns the full card list for a user. Restrict to self, or an admin
        // (device:read) acting within a tenant they manage — same treatment as
        // /search/{serial}. The controller no longer accepts isAuthenticated()
        // alone for cross-user reads.
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(UnauthorizedException::new);
        if (!userId.equals(currentUser.getId())) {
            if (!rbacService.hasPermission(NFC_READ_PERMISSION)) {
                log.warn("AUDIT: NFC card list refused — non-owner caller {} lacks {} for target {}",
                        currentUser.getId(), NFC_READ_PERMISSION, userId);
                throw new UnauthorizedException(
                        "You may only list your own NFC cards unless you are an administrator");
            }
            assertTargetWithinManageableTenant(userId, currentUser);
        }
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
