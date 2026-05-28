package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
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

    private static final String SERIAL = "04A2B3C4D5E6F7";

    @Test
    void supports_returnsNfcDocument() {
        NfcDocumentVerifyMfaStepHandler handler =
                new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, false);
        assertThat(handler.supports()).isEqualTo(AuthMethodType.NFC_DOCUMENT);
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

        NfcDocumentVerifyMfaStepHandler handler =
                new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, false);

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
        NfcDocumentVerifyMfaStepHandler handler =
                new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, false);

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

        NfcDocumentVerifyMfaStepHandler handler =
                new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, true);

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

        NfcDocumentVerifyMfaStepHandler handler =
                new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, true);

        MfaStepResult result = handler.verify(session(userId), user, Map.of("nfcData", SERIAL));

        assertThat(result.valid()).isFalse();
    }

    @Test
    void flagOn_failsWhenNfcDataMissing() {
        UUID userId = UUID.randomUUID();
        NfcDocumentVerifyMfaStepHandler handler =
                new NfcDocumentVerifyMfaStepHandler(nfcCardRepository, true);

        MfaStepResult result = handler.verify(session(userId), userMock(userId), Map.of());

        assertThat(result.valid()).isFalse();
        verify(nfcCardRepository, never())
                .findByCardSerialAndUserIdAndIsActiveTrue(any(), any());
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
