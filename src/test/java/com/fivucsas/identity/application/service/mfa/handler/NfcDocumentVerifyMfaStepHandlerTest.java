package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link NfcDocumentVerifyMfaStepHandler}.
 *
 * <p>S9 (security review): a card serial is not a secret, so serial-only NFC
 * verification must fail closed by default and only pass when the legacy
 * opt-in flag {@code fivucsas.nfc.serial-only-auth-enabled} is explicitly true.
 */
@ExtendWith(MockitoExtension.class)
class NfcDocumentVerifyMfaStepHandlerTest {

    @Mock private NfcCardRepositoryPort nfcCardRepository;
    @Mock private UserRepository userRepository;

    private static final String SERIAL = "04A2B3C4D5E6F7";

    /** serial-only ON, cross-membership OFF (the prod-today config). */
    private NfcDocumentVerifyMfaStepHandler handler(boolean serialOnly) {
        return new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, userRepository, serialOnly, false);
    }

    /** Both flags ON (the new cross-membership behavior under test). */
    private NfcDocumentVerifyMfaStepHandler handlerCrossMembership() {
        return new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, userRepository, true, true);
    }

    @Test
    void supports_returnsNfcDocument() {
        assertThat(handler(false).supports()).isEqualTo(AuthMethodType.NFC_DOCUMENT);
    }

    // ============== Fail-closed (flag OFF, default) ==============

    @Test
    void flagOff_failsClosed_evenWhenSerialMatchesActiveCard() {
        // Default (gate ON): even a serial that maps to an active enrolled card
        // MUST NOT pass — a serial is not authentication.
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        // The repository would normally return a match; the handler must not
        // even consult it on the fail-closed path.
        lenient().when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.of(activeCard(userId)));

        NfcDocumentVerifyMfaStepHandler handler = handler(false);

        MfaStepResult result = handler.verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isFalse();
        assertThat(result.isChallenge()).isFalse();
        // Fail-closed short-circuits before any repository lookup.
        verify(nfcCardRepository, never())
                .findByCardSerialAndUserIdAndIsActiveTrue(any(), any());
    }

    @Test
    void flagOff_failsClosed_whenNfcDataMissing() {
        UUID userId = UUID.randomUUID();
        NfcDocumentVerifyMfaStepHandler handler = handler(false);

        MfaStepResult result = handler.verify(session(userId), userMock(userId), Map.of());

        assertThat(result.valid()).isFalse();
        verify(nfcCardRepository, never())
                .findByCardSerialAndUserIdAndIsActiveTrue(any(), any());
    }

    // ============== Legacy opt-in (flag ON) ==============

    @Test
    void flagOn_passesWhenSerialMatchesActiveCard() {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.of(activeCard(userId)));

        NfcDocumentVerifyMfaStepHandler handler = handler(true);

        MfaStepResult result = handler.verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isTrue();
        verify(nfcCardRepository).findByCardSerialAndUserIdAndIsActiveTrue(eq(SERIAL), eq(userId));
    }

    @Test
    void flagOn_failsWhenSerialDoesNotMatch() {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.empty());

        NfcDocumentVerifyMfaStepHandler handler = handler(true);

        MfaStepResult result = handler.verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isFalse();
    }

    @Test
    void flagOn_failsWhenNfcDataMissing() {
        UUID userId = UUID.randomUUID();
        NfcDocumentVerifyMfaStepHandler handler = handler(true);

        MfaStepResult result = handler.verify(session(userId), userMock(userId), Map.of());

        assertThat(result.valid()).isFalse();
        verify(nfcCardRepository, never())
                .findByCardSerialAndUserIdAndIsActiveTrue(any(), any());
    }

    // ============== Cross-membership resolution (both flags ON) ==============

    @Test
    void crossMembershipOff_doesNotConsultSiblingMemberships_whenActiveRowMisses() {
        // serial-only ON but cross-membership OFF (prod-today): an active-row miss
        // fails and the sibling lookup is NEVER attempted (byte-identical to legacy).
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.empty());

        MfaStepResult result = handler(true).verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isFalse();
        verify(nfcCardRepository, never())
                .findActiveCardBySerialForIdentityExcludingTenant(any(), any(), any());
        verify(userRepository, never()).findIdentityIdById(any());
    }

    @Test
    void crossMembershipOn_passesWhenSerialMatchesSiblingMembershipCard() {
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID siblingUserId = UUID.randomUUID();
        User user = userMock(userId);

        // Active membership row has no matching card...
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.empty());
        when(userRepository.findIdentityIdById(userId)).thenReturn(Optional.of(identityId));
        when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));
        // ...but a sibling membership of the same identity holds an active card.
        NfcCard sibling = org.mockito.Mockito.mock(NfcCard.class);
        User siblingUser = userMock(siblingUserId);
        lenient().when(sibling.getUser()).thenReturn(siblingUser);
        when(nfcCardRepository.findActiveCardBySerialForIdentityExcludingTenant(SERIAL, identityId, tenantId))
                .thenReturn(Optional.of(sibling));

        MfaStepResult result = handlerCrossMembership().verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isTrue();
        verify(nfcCardRepository)
                .findActiveCardBySerialForIdentityExcludingTenant(eq(SERIAL), eq(identityId), eq(tenantId));
    }

    @Test
    void crossMembershipOn_failsWhenNoSiblingMembershipMatch() {
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        User user = userMock(userId);

        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.empty());
        when(userRepository.findIdentityIdById(userId)).thenReturn(Optional.of(identityId));
        when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));
        when(nfcCardRepository.findActiveCardBySerialForIdentityExcludingTenant(SERIAL, identityId, tenantId))
                .thenReturn(Optional.empty());

        MfaStepResult result = handlerCrossMembership().verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isFalse();
    }

    @Test
    void crossMembershipOn_failsWhenUserHasNoIdentity() {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);

        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.empty());
        when(userRepository.findIdentityIdById(userId)).thenReturn(Optional.empty());
        lenient().when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(UUID.randomUUID()));

        MfaStepResult result = handlerCrossMembership().verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isFalse();
        verify(nfcCardRepository, never())
                .findActiveCardBySerialForIdentityExcludingTenant(any(), any(), any());
    }

    @Test
    void crossMembershipOn_activeRowMatchShortCircuits_noSiblingLookup() {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(SERIAL, userId))
                .thenReturn(Optional.of(activeCard(userId)));

        MfaStepResult result = handlerCrossMembership().verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isTrue();
        verify(nfcCardRepository, never())
                .findActiveCardBySerialForIdentityExcludingTenant(any(), any(), any());
        verify(userRepository, never()).findIdentityIdById(any());
    }

    // ============== Helpers ==============

    private User userMock(UUID userId) {
        User user = org.mockito.Mockito.mock(User.class);
        lenient().when(user.getId()).thenReturn(userId);
        return user;
    }

    private MfaSession session(UUID userId) {
        return MfaSession.builder()
                .id(UUID.randomUUID())
                .sessionToken("test-session-token")
                .userId(userId)
                .tenantId(UUID.randomUUID())
                .flowId(UUID.randomUUID())
                .currentStep(2)
                .totalSteps(2)
                .stepsData("[\"PASSWORD\"]")
                .build();
    }

    private NfcCard activeCard(UUID userId) {
        // The handler only inspects Optional.isPresent(); the card contents are
        // irrelevant, so a bare mock suffices.
        return org.mockito.Mockito.mock(NfcCard.class);
    }
}
