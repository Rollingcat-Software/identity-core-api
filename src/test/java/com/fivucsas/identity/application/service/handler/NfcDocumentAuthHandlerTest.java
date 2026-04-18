package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NfcDocumentAuthHandlerTest {

    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;
    @Mock private NfcCardRepositoryPort nfcCardRepository;

    @InjectMocks
    private NfcDocumentAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnNfcDocument() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.NFC_DOCUMENT);
    }

    @Test
    void validate_WhenNfcCardNotEnrolled_ShouldReturnFailure() {
        // given — card serial provided but no enrolled active card for this user
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(session.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(userId);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue("someNfcPayload", userId))
                .thenReturn(Optional.empty());

        // when
        StepResult result = handler.validate(session, step, Map.of("nfcData", "someNfcPayload"));

        // then
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("not enrolled");
    }

    @Test
    void validate_WhenNfcCardFound_ShouldReturnSuccess() {
        // given
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(session.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(userId);
        when(session.getId()).thenReturn(UUID.randomUUID());

        NfcCard card = mock(NfcCard.class);
        when(card.getCardType()).thenReturn("ID_CARD");
        when(nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue("validSerial", userId))
                .thenReturn(Optional.of(card));

        // when
        StepResult result = handler.validate(session, step, Map.of("nfcData", "validSerial"));

        // then
        assertThat(result.isSuccess()).isTrue();
        verify(card).markUsed();
        verify(nfcCardRepository).save(card);
    }

    @Test
    void validate_WhenMissingNfcData_ShouldReturnRequiresCardSerial() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("NFC card serial is required");
    }

    @Test
    void validate_WhenNoUser_ShouldReturnFailure() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("nfcData", "data"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }
}
