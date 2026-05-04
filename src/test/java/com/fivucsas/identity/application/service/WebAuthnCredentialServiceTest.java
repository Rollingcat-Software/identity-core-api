package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("WebAuthnCredentialService")
class WebAuthnCredentialServiceTest {

    @Mock private WebAuthnCredentialRepositoryPort credentialRepository;
    @Mock private ManageEnrollmentUseCase manageEnrollmentUseCase;

    @InjectMocks
    private WebAuthnCredentialService service;

    private UUID userId;
    private User user;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        user = mock(User.class);
        lenient().when(user.getId()).thenReturn(userId);
    }

    @Nested
    @DisplayName("saveCredential")
    class SaveCredential {

        @Test
        @DisplayName("persists and auto-completes FINGERPRINT enrollment for platform transport")
        void platformTransportTriggersFingerprintEnrollment() {
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getUser()).thenReturn(user);
            when(c.getTransports()).thenReturn("internal");
            when(credentialRepository.save(c)).thenReturn(c);

            WebAuthnCredential saved = service.saveCredential(c);

            assertThat(saved).isSameAs(c);
            verify(credentialRepository).save(c);
            verify(manageEnrollmentUseCase).completeEnrollment(userId, AuthMethodType.FINGERPRINT, "{}");
        }

        @Test
        @DisplayName("persists and auto-completes HARDWARE_KEY enrollment for roaming transport")
        void roamingTransportTriggersHardwareKeyEnrollment() {
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getUser()).thenReturn(user);
            when(c.getTransports()).thenReturn("usb,nfc");
            when(credentialRepository.save(c)).thenReturn(c);

            service.saveCredential(c);

            verify(manageEnrollmentUseCase).completeEnrollment(userId, AuthMethodType.HARDWARE_KEY, "{}");
        }

        @Test
        @DisplayName("swallows enrollment-side-effect failure (credential is source of truth)")
        void swallowsEnrollmentFailure() {
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getUser()).thenReturn(user);
            when(c.getTransports()).thenReturn("internal");
            when(credentialRepository.save(c)).thenReturn(c);
            doThrow(new RuntimeException("downstream offline"))
                    .when(manageEnrollmentUseCase)
                    .completeEnrollment(any(), any(), any());

            // Must not propagate — credential save already committed.
            WebAuthnCredential saved = service.saveCredential(c);

            assertThat(saved).isSameAs(c);
        }
    }

    @Nested
    @DisplayName("updateSignCount")
    class UpdateSignCount {

        @Test
        @DisplayName("advances counter and persists when new is strictly greater")
        void advancesAndSaves() {
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getSignCount()).thenReturn(5L);

            service.updateSignCount(c, 6L);

            verify(c).updateSignCount(6L);
            verify(credentialRepository).save(c);
        }

        @Test
        @DisplayName("no-ops when new equals stored (both-zero spec case)")
        void noopOnEqualCounter() {
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getSignCount()).thenReturn(0L);

            service.updateSignCount(c, 0L);

            verify(c, never()).updateSignCount(anyLong());
            verify(credentialRepository, never()).save(any());
        }

        @Test
        @DisplayName("no-ops when new is less than stored (caller expected to reject upstream)")
        void noopOnRegression() {
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getSignCount()).thenReturn(10L);

            service.updateSignCount(c, 5L);

            verify(c, never()).updateSignCount(anyLong());
            verify(credentialRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("deleteById")
    class DeleteById {

        @Test
        @DisplayName("revokes FINGERPRINT enrollment when last platform credential removed")
        void revokesEnrollmentWhenLastPlatformCredentialRemoved() {
            UUID id = UUID.randomUUID();
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getUser()).thenReturn(user);
            when(c.getTransports()).thenReturn("internal");
            when(credentialRepository.findById(id)).thenReturn(Optional.of(c));
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of());

            service.deleteById(id);

            verify(credentialRepository).deleteById(id);
            verify(manageEnrollmentUseCase).revokeEnrollment(userId, AuthMethodType.FINGERPRINT);
        }

        @Test
        @DisplayName("keeps enrollment when another platform credential remains")
        void keepsEnrollmentWhenOtherPlatformCredentialRemains() {
            UUID id = UUID.randomUUID();
            WebAuthnCredential deleted = mock(WebAuthnCredential.class);
            when(deleted.getUser()).thenReturn(user);
            when(deleted.getTransports()).thenReturn("internal");

            WebAuthnCredential remaining = mock(WebAuthnCredential.class);
            when(remaining.getTransports()).thenReturn("internal");

            when(credentialRepository.findById(id)).thenReturn(Optional.of(deleted));
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of(remaining));

            service.deleteById(id);

            verify(credentialRepository).deleteById(id);
            verify(manageEnrollmentUseCase, never()).revokeEnrollment(any(), any());
        }

        @Test
        @DisplayName("throws ResourceNotFoundException when id is unknown")
        void throwsWhenNotFound() {
            UUID id = UUID.randomUUID();
            when(credentialRepository.findById(id)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.deleteById(id))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("deleteByCredentialId")
    class DeleteByCredentialId {

        @Test
        @DisplayName("revokes FINGERPRINT enrollment when last platform credential removed (parity with deleteById)")
        void revokesEnrollmentWhenLastPlatformCredentialRemoved() {
            // Copilot review on PR #66: deleteByCredentialId previously skipped
            // revokeWebAuthnEnrollmentIfNeeded, leaving stale ENROLLED rows.
            WebAuthnCredential c = mock(WebAuthnCredential.class);
            when(c.getUser()).thenReturn(user);
            when(c.getTransports()).thenReturn("internal");
            when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(c));
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of());

            service.deleteByCredentialId("credId");

            verify(credentialRepository).deleteByCredentialId("credId");
            verify(manageEnrollmentUseCase).revokeEnrollment(userId, AuthMethodType.FINGERPRINT);
        }

        @Test
        @DisplayName("keeps enrollment when another platform credential remains")
        void keepsEnrollmentWhenOtherPlatformCredentialRemains() {
            WebAuthnCredential deleted = mock(WebAuthnCredential.class);
            when(deleted.getUser()).thenReturn(user);
            when(deleted.getTransports()).thenReturn("internal");

            WebAuthnCredential remaining = mock(WebAuthnCredential.class);
            when(remaining.getTransports()).thenReturn("internal");

            when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(deleted));
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of(remaining));

            service.deleteByCredentialId("credId");

            verify(credentialRepository).deleteByCredentialId("credId");
            verify(manageEnrollmentUseCase, never()).revokeEnrollment(any(), any());
        }

        @Test
        @DisplayName("throws ResourceNotFoundException when credentialId is unknown")
        void throwsWhenUnknown() {
            when(credentialRepository.findByCredentialId("missing")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.deleteByCredentialId("missing"))
                    .isInstanceOf(ResourceNotFoundException.class);
            verify(credentialRepository, never()).deleteByCredentialId(eq("missing"));
        }
    }
}
