package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.NfcCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface NfcCardRepository extends JpaRepository<NfcCard, UUID> {

    Optional<NfcCard> findByCardSerialAndTenantId(String cardSerial, UUID tenantId);

    Optional<NfcCard> findByCardSerialAndIsActiveTrue(String cardSerial);

    Optional<NfcCard> findByCardSerialAndUserIdAndIsActiveTrue(String cardSerial, UUID userId);

    List<NfcCard> findByCardSerial(String cardSerial);

    List<NfcCard> findAllByCardSerialAndTenantId(String cardSerial, UUID tenantId);

    List<NfcCard> findByUserIdAndIsActiveTrue(UUID userId);

    List<NfcCard> findByUserId(UUID userId);

    List<NfcCard> findByTenantIdAndIsActiveTrue(UUID tenantId);

    boolean existsByCardSerialAndTenantId(String cardSerial, UUID tenantId);

    boolean existsByCardSerialAndTenantIdAndIsActiveTrue(String cardSerial, UUID tenantId);

    void deleteByUserIdAndTenantId(UUID userId, UUID tenantId);

    /**
     * Cross-membership: whether ANY active NFC card exists across all the
     * (non-deleted) memberships of a person (identity), EXCLUDING the requesting
     * membership's tenant (Phase-5 cross-membership enrollment resolution, NFC only).
     *
     * <p><b>Native query</b> — deliberately joins {@code nfc_cards → users} on the
     * person's {@code identity_id} and bypasses the Hibernate {@code @Filter(tenantFilter)}
     * (which is applied to {@code users}/{@code user_enrollments}, NOT to
     * {@code nfc_cards}). This mirrors the established controlled cross-tenant read
     * {@link UserRepository#findCanonicalEnrollment}. Guards re-applied explicitly:
     * {@code u.deleted_at IS NULL} (soft-delete) and {@code c.is_active = true}.
     * Reached ONLY when the {@code app.identity.cross-membership-enrollment-resolution}
     * flag is ON and the active-membership card lookup already missed.</p>
     *
     * @param identityId      the person whose linked memberships to scan
     * @param excludeTenantId the requesting membership's tenant (its own cards are
     *                        already handled by the active-row lookup, so they are
     *                        excluded — a hit here is genuinely cross-membership)
     */
    @Query(value =
            "SELECT EXISTS (SELECT 1 FROM nfc_cards c "
            + "JOIN users u ON u.id = c.user_id "
            + "WHERE u.identity_id = :identityId "
            + "  AND u.tenant_id <> :excludeTenantId "
            + "  AND u.deleted_at IS NULL "
            + "  AND c.is_active = true)",
            nativeQuery = true)
    boolean existsActiveCardForIdentityExcludingTenant(@Param("identityId") UUID identityId,
                                                       @Param("excludeTenantId") UUID excludeTenantId);

    /**
     * Cross-membership: resolves an ACTIVE NFC card matching {@code cardSerial}
     * across all the (non-deleted) memberships of a person (identity), EXCLUDING
     * the requesting membership's tenant. Backs the NFC verify step when the
     * active-row serial lookup missed but the card is enrolled under a sibling
     * membership (Phase-5 cross-membership enrollment resolution, NFC only).
     *
     * <p><b>Native query</b> for the same reason / with the same guards as
     * {@link #existsActiveCardForIdentityExcludingTenant}. Returns the matched
     * card (oldest enrolled first for determinism) so the caller can audit the
     * sibling {@code user_id} that owned it. {@code cardSerial} must already be in
     * the canonical UPPERHEX form ({@code NfcSerial.canonicalize}).</p>
     */
    @Query(value =
            "SELECT * FROM nfc_cards c "
            + "JOIN users u ON u.id = c.user_id "
            + "WHERE c.card_serial = :cardSerial "
            + "  AND u.identity_id = :identityId "
            + "  AND u.tenant_id <> :excludeTenantId "
            + "  AND u.deleted_at IS NULL "
            + "  AND c.is_active = true "
            + "ORDER BY c.enrolled_at ASC NULLS LAST, c.created_at ASC "
            + "LIMIT 1",
            nativeQuery = true)
    Optional<NfcCard> findActiveCardBySerialForIdentityExcludingTenant(
            @Param("cardSerial") String cardSerial,
            @Param("identityId") UUID identityId,
            @Param("excludeTenantId") UUID excludeTenantId);
}
