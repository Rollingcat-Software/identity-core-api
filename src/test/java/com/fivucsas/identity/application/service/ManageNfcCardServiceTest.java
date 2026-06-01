package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for {@link ManageNfcCardService}, the application-level
 * home of the NFC enrollment / verify / lookup logic that used to live (with
 * controller-level {@code @Transactional}) inside {@code NfcController}.
 *
 * <p>P1-Q9, quality review 2026-05-01: behaviour parity is the contract. Each
 * test below asserts a status branch that the controller previously emitted
 * via {@code Map.of("success", false, "message", "...")} bodies — now
 * encoded as a {@link ManageNfcCardService.EnrollResult.Status} or
 * {@link ManageNfcCardService.DeactivateOutcome} so the controller does no
 * persistence work of its own.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("ManageNfcCardService — P1-Q9 controller-tx-move regression")
class ManageNfcCardServiceTest {

    @Mock private NfcCardRepositoryPort nfcCardRepository;
    @Mock private UserRepository userRepository;
    @Mock private RbacAuthorizationService rbacService;
    @Mock private TenantScopeResolver tenantScopeResolver;
    @Mock private ManageEnrollmentUseCase manageEnrollmentUseCase;

    @InjectMocks
    private ManageNfcCardService service;

    private User currentUser;
    private Tenant tenant;
    private UUID tenantId;
    private UUID currentUserId;

    @BeforeEach
    void setUpCurrentUser() {
        tenantId = UUID.randomUUID();
        currentUserId = UUID.randomUUID();
        tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        currentUser = mock(User.class);
        when(currentUser.getId()).thenReturn(currentUserId);
        when(currentUser.getTenant()).thenReturn(tenant);
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(currentUser));
        // Default: a tenant-bound caller (scoped to `tenantId`, not ROOT).
        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(tenantScopeResolver.currentScope()).thenReturn(tenantId);
    }

    @Test
    @DisplayName("enrollCard → CONFLICT when an active card with the same serial already exists in the tenant")
    void enrollCard_WhenSerialActivelyEnrolledInTenant_ShouldReturnConflict() {
        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("AABB", tenantId))
                .thenReturn(true);

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(null, "AABB", "MIFARE", "Test card");

        assertThat(result.status()).isEqualTo(ManageNfcCardService.EnrollResult.Status.CONFLICT);
        verify(nfcCardRepository, never()).save(any(NfcCard.class));
        verify(manageEnrollmentUseCase, never()).startEnrollment(any(), any(), any());
    }

    @Test
    @DisplayName("enrollCard → USER_NOT_FOUND when the requested target user does not exist")
    void enrollCard_WhenTargetUserMissing_ShouldReturnUserNotFound() {
        UUID targetUserId = UUID.randomUUID();
        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("CCDD", tenantId))
                .thenReturn(false);
        when(userRepository.findById(targetUserId)).thenReturn(Optional.empty());

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(targetUserId, "CCDD", "MIFARE", null);

        assertThat(result.status()).isEqualTo(ManageNfcCardService.EnrollResult.Status.USER_NOT_FOUND);
        verify(nfcCardRepository, never()).save(any(NfcCard.class));
    }

    @Test
    @DisplayName("enrollCard → OK auto-completes the NFC_DOCUMENT enrollment record (auto-complete side-effect parity)")
    void enrollCard_WhenSuccessful_ShouldCallStartEnrollmentForNfcDocument() {
        UUID targetUserId = UUID.randomUUID();
        User targetUser = mock(User.class);
        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("EEFF", tenantId))
                .thenReturn(false);
        when(nfcCardRepository.findByCardSerialAndTenantId("EEFF", tenantId))
                .thenReturn(Optional.empty());
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));
        // builder() / save() roundtrip — return a stub card with the saved state.
        when(nfcCardRepository.save(any(NfcCard.class))).thenAnswer(invocation -> {
            NfcCard incoming = invocation.getArgument(0);
            // The builder leaves id null until JPA assigns; for the assertion below
            // we just need a non-null UUID to flow back to the caller.
            NfcCard saved = mock(NfcCard.class);
            when(saved.getId()).thenReturn(UUID.randomUUID());
            when(saved.getCardSerial()).thenReturn(incoming.getCardSerial());
            return saved;
        });

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(targetUserId, "EEFF", "MIFARE", "personal");

        assertThat(result.status()).isEqualTo(ManageNfcCardService.EnrollResult.Status.OK);
        assertThat(result.targetUserId()).isEqualTo(targetUserId);
        assertThat(result.card()).isNotNull();
        verify(manageEnrollmentUseCase, times(1))
                .startEnrollment(eq(targetUserId), eq(tenantId), eq(AuthMethodType.NFC_DOCUMENT));
    }

    // ------------------------------------------------------------------
    // P1-8: re-enroll must not silently reactivate a REVOKED card nor
    // silently reassign ownership. Both require explicit re-authorization.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("enrollCard → CARD_REVOKED when re-enrolling a revoked card without re-authorization")
    void enrollCard_WhenExistingCardRevoked_AndNotReauthorized_ShouldRefuse() {
        UUID targetUserId = currentUserId;
        NfcCard revoked = mock(NfcCard.class);
        when(revoked.isActive()).thenReturn(false);
        when(revoked.getRevokedAt()).thenReturn(java.time.Instant.now());

        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("AABB", tenantId))
                .thenReturn(false);
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(currentUser));
        when(nfcCardRepository.findByCardSerialAndTenantId("AABB", tenantId))
                .thenReturn(Optional.of(revoked));

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(null, "AABB", "MIFARE", "Test card");

        assertThat(result.status()).isEqualTo(ManageNfcCardService.EnrollResult.Status.CARD_REVOKED);
        verify(nfcCardRepository, never()).save(any(NfcCard.class));
        verify(revoked, never()).activate();
    }

    @Test
    @DisplayName("enrollCard → reactivates a revoked card when reauthorize=true")
    void enrollCard_WhenExistingCardRevoked_AndReauthorized_ShouldReactivate() {
        UUID targetUserId = currentUserId;
        NfcCard revoked = mock(NfcCard.class);
        when(revoked.isActive()).thenReturn(false);
        when(revoked.getRevokedAt()).thenReturn(java.time.Instant.now());
        when(revoked.getUser()).thenReturn(currentUser);

        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("AABB", tenantId))
                .thenReturn(false);
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(currentUser));
        when(nfcCardRepository.findByCardSerialAndTenantId("AABB", tenantId))
                .thenReturn(Optional.of(revoked));
        when(nfcCardRepository.save(any(NfcCard.class))).thenAnswer(inv -> {
            NfcCard saved = mock(NfcCard.class);
            when(saved.getId()).thenReturn(UUID.randomUUID());
            when(saved.getCardSerial()).thenReturn("AABB");
            return saved;
        });

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(null, "AABB", "MIFARE", "Test card", true);

        assertThat(result.status()).isEqualTo(ManageNfcCardService.EnrollResult.Status.OK);
        verify(revoked).activate();
        verify(nfcCardRepository).save(any(NfcCard.class));
    }

    @Test
    @DisplayName("enrollCard → OWNED_BY_ANOTHER_USER when re-pointing a card to a different owner without re-authorization")
    void enrollCard_WhenCardOwnedByAnotherUser_AndNotReauthorized_ShouldRefuse() {
        UUID otherOwnerId = UUID.randomUUID();
        UUID targetUserId = UUID.randomUUID();
        User otherOwner = mock(User.class);
        when(otherOwner.getId()).thenReturn(otherOwnerId);
        User targetUser = mock(User.class);

        // An ACTIVE card currently belongs to otherOwner; a new enroll targets targetUser.
        NfcCard existing = mock(NfcCard.class);
        when(existing.isActive()).thenReturn(true);
        when(existing.getUser()).thenReturn(otherOwner);

        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("CCDD", tenantId))
                .thenReturn(false);
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));
        when(nfcCardRepository.findByCardSerialAndTenantId("CCDD", tenantId))
                .thenReturn(Optional.of(existing));

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(targetUserId, "CCDD", "MIFARE", null);

        assertThat(result.status())
                .isEqualTo(ManageNfcCardService.EnrollResult.Status.OWNED_BY_ANOTHER_USER);
        verify(nfcCardRepository, never()).save(any(NfcCard.class));
        verify(existing, never()).setUser(any());
    }

    @Test
    @DisplayName("enrollCard → OK re-enroll of the SAME owner's still-active card (benign reactivation unaffected)")
    void enrollCard_WhenSameOwnerActiveCard_ShouldReenrollWithoutReauthorization() {
        NfcCard existing = mock(NfcCard.class);
        when(existing.isActive()).thenReturn(true);
        when(existing.getUser()).thenReturn(currentUser); // same owner as target (self-enroll)

        when(nfcCardRepository.existsByCardSerialAndTenantIdAndIsActiveTrue("EE11", tenantId))
                .thenReturn(false);
        when(userRepository.findById(currentUserId)).thenReturn(Optional.of(currentUser));
        when(nfcCardRepository.findByCardSerialAndTenantId("EE11", tenantId))
                .thenReturn(Optional.of(existing));
        when(nfcCardRepository.save(any(NfcCard.class))).thenAnswer(inv -> {
            NfcCard saved = mock(NfcCard.class);
            when(saved.getId()).thenReturn(UUID.randomUUID());
            when(saved.getCardSerial()).thenReturn("EE11");
            return saved;
        });

        ManageNfcCardService.EnrollResult result =
                service.enrollCard(null, "EE11", "MIFARE", "Personal");

        assertThat(result.status()).isEqualTo(ManageNfcCardService.EnrollResult.Status.OK);
        verify(existing).activate();
        verify(existing).setUser(currentUser);
    }

    @Test
    @DisplayName("removeAllUserEnrollments → returns 0 when the user has no NFC cards (parity with previous controller body)")
    void removeAllUserEnrollments_WhenUserHasNoCards_ShouldReturnZero() {
        UUID userId = UUID.randomUUID();
        when(nfcCardRepository.findByUserId(userId)).thenReturn(List.of());

        int deactivated = service.removeAllUserEnrollments(userId);

        assertThat(deactivated).isZero();
        verify(nfcCardRepository, never()).saveAll(any());
    }

    @Test
    @DisplayName("deactivateCard → NOT_FOUND when the card belongs to a different user")
    void deactivateCard_WhenCardNotInUserList_ShouldReturnNotFound() {
        when(nfcCardRepository.findByUserId(currentUserId)).thenReturn(List.of());

        ManageNfcCardService.DeactivateOutcome outcome =
                service.deactivateCard(UUID.randomUUID());

        assertThat(outcome).isEqualTo(ManageNfcCardService.DeactivateOutcome.NOT_FOUND);
    }

    // ------------------------------------------------------------------
    // S11 (security review): searchByCardSerial must be tenant-scoped so a
    // tenant-bound caller cannot enumerate card owners in other tenants.
    // ------------------------------------------------------------------

    @Test
    @DisplayName("searchByCardSerial → tenant-scoped lookup for a tenant-bound caller (S11 cross-tenant leak)")
    void searchByCardSerial_WhenCallerHasTenant_ShouldOnlyQueryOwnTenant() {
        NfcCard inTenantCard = mock(NfcCard.class);
        when(nfcCardRepository.findAllByCardSerialAndTenantId("SERIAL-1", tenantId))
                .thenReturn(List.of(inTenantCard));

        List<NfcCard> results = service.searchByCardSerial("SERIAL-1");

        assertThat(results).containsExactly(inTenantCard);
        verify(nfcCardRepository, times(1)).findAllByCardSerialAndTenantId("SERIAL-1", tenantId);
        // Must NOT fall back to the unscoped cross-tenant query.
        verify(nfcCardRepository, never()).findByCardSerial(any());
    }

    @Test
    @DisplayName("searchByCardSerial → unscoped global lookup for ROOT (no tenant attached)")
    void searchByCardSerial_WhenCallerHasNoTenant_ShouldQueryGlobally() {
        // ROOT: unrestricted scope → unscoped global lookup.
        when(tenantScopeResolver.isUnrestricted()).thenReturn(true);
        NfcCard anyCard = mock(NfcCard.class);
        when(nfcCardRepository.findByCardSerial("SERIAL-2")).thenReturn(List.of(anyCard));

        List<NfcCard> results = service.searchByCardSerial("SERIAL-2");

        assertThat(results).containsExactly(anyCard);
        verify(nfcCardRepository, times(1)).findByCardSerial("SERIAL-2");
        verify(nfcCardRepository, never()).findAllByCardSerialAndTenantId(any(), any());
    }
}
