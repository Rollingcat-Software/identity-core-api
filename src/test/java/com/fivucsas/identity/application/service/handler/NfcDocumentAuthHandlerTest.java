package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NfcDocumentAuthHandlerTest {

    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private NfcDocumentAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnNfcDocument() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.NFC_DOCUMENT);
    }

    @Test
    void validate_WhenNfcDataProvided_ShouldReturnPendingMessage() {
        User user = mock(User.class);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());

        StepResult result = handler.validate(session, step, Map.of("nfcData", "someNfcPayload"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("not yet available");
    }

    @Test
    void validate_WhenMissingNfcData_ShouldReturnRequiresHardware() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("NFC hardware");
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
