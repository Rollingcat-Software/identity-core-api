package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.BiometricConsentRequest;
import com.fivucsas.identity.application.dto.response.BiometricConsentResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.BiometricConsentResolver.CanonicalTarget;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.IdentityTenantBiometricConsent;
import com.fivucsas.identity.repository.IdentityTenantBiometricConsentRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link BiometricConsentService} — the Model A Phase 3
 * consent-management + canonical-routing orchestration.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("BiometricConsentService")
class BiometricConsentServiceTest {

    @Mock private IdentityTenantBiometricConsentRepository consentRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuditLogPort auditLogPort;

    @InjectMocks private BiometricConsentService service;

    private UUID identityId;
    private UUID tenantId;
    private UUID actorUserId;

    @BeforeEach
    void setUp() {
        identityId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        actorUserId = UUID.randomUUID();
    }

    @Nested
    @DisplayName("setConsent (grant / revoke)")
    class SetConsent {

        @Test
        @DisplayName("grants a new consent row when the caller has a membership in the tenant")
        void grantsNewConsent() {
            when(userRepository.identityHasMembershipInTenant(identityId, tenantId)).thenReturn(true);
            when(consentRepository.findByIdentityIdAndTenantIdAndMethod(identityId, tenantId, "FACE"))
                    .thenReturn(Optional.empty());
            when(consentRepository.save(any(IdentityTenantBiometricConsent.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            BiometricConsentResponse resp = service.setConsent(identityId, actorUserId,
                    new BiometricConsentRequest(tenantId, "FACE", true));

            assertThat(resp.granted()).isTrue();
            assertThat(resp.tenantId()).isEqualTo(tenantId);
            assertThat(resp.method()).isEqualTo("FACE");
            assertThat(resp.grantedAt()).isNotNull();
            assertThat(resp.revokedAt()).isNull();

            ArgumentCaptor<String> evt = ArgumentCaptor.forClass(String.class);
            verify(auditLogPort).logSecurityEvent(eq(actorUserId.toString()), evt.capture(),
                    isNull(), anyString());
            assertThat(evt.getValue()).isEqualTo("BIOMETRIC_CONSENT_CHANGED");
        }

        @Test
        @DisplayName("normalizes blank method to null (= all methods)")
        void normalizesBlankMethodToNull() {
            when(userRepository.identityHasMembershipInTenant(identityId, tenantId)).thenReturn(true);
            when(consentRepository.findByIdentityIdAndTenantIdAndMethod(identityId, tenantId, null))
                    .thenReturn(Optional.empty());
            when(consentRepository.save(any(IdentityTenantBiometricConsent.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            BiometricConsentResponse resp = service.setConsent(identityId, actorUserId,
                    new BiometricConsentRequest(tenantId, "  ", true));

            assertThat(resp.method()).isNull();
        }

        @Test
        @DisplayName("revoke flips an existing row and stamps revoked_at")
        void revokeFlipsExisting() {
            IdentityTenantBiometricConsent existing = IdentityTenantBiometricConsent.builder()
                    .identityId(identityId).tenantId(tenantId).method("FACE").build();
            existing.apply(true);
            when(userRepository.identityHasMembershipInTenant(identityId, tenantId)).thenReturn(true);
            when(consentRepository.findByIdentityIdAndTenantIdAndMethod(identityId, tenantId, "FACE"))
                    .thenReturn(Optional.of(existing));
            when(consentRepository.save(any(IdentityTenantBiometricConsent.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            BiometricConsentResponse resp = service.setConsent(identityId, actorUserId,
                    new BiometricConsentRequest(tenantId, "FACE", false));

            assertThat(resp.granted()).isFalse();
            assertThat(resp.revokedAt()).isNotNull();
        }

        @Test
        @DisplayName("rejects managing consent for a tenant where the caller has NO membership")
        void rejectsForeignTenant() {
            when(userRepository.identityHasMembershipInTenant(identityId, tenantId)).thenReturn(false);

            assertThatThrownBy(() -> service.setConsent(identityId, actorUserId,
                    new BiometricConsentRequest(tenantId, "FACE", true)))
                    .isInstanceOf(UnauthorizedException.class);

            verify(consentRepository, never()).save(any());
            verify(auditLogPort, never()).logSecurityEvent(any(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("resolveConsentedCanonicalTarget (default-DENY routing)")
    class Resolve {

        private final UUID requestingUser = UUID.randomUUID();
        private final UUID requestingTenant = UUID.randomUUID();
        private final UUID canonicalUser = UUID.randomUUID();
        private final UUID canonicalTenant = UUID.randomUUID();

        private void wireIdentityAndCanonical() {
            when(userRepository.findTenantIdById(requestingUser)).thenReturn(Optional.of(requestingTenant));
            when(userRepository.findIdentityIdById(requestingUser)).thenReturn(Optional.of(identityId));
            when(userRepository.findCanonicalEnrollment(identityId, "FACE", requestingTenant))
                    .thenReturn(List.<Object[]>of(new Object[]{canonicalUser, canonicalTenant}));
        }

        @Test
        @DisplayName("returns target when a canonical enrollment exists AND consent is granted")
        void grantedRoutes() {
            wireIdentityAndCanonical();
            IdentityTenantBiometricConsent c = IdentityTenantBiometricConsent.builder()
                    .identityId(identityId).tenantId(requestingTenant).method("FACE").build();
            c.apply(true);
            when(consentRepository.findApplicable(identityId, requestingTenant, "FACE"))
                    .thenReturn(List.of(c));

            Optional<CanonicalTarget> target =
                    service.resolveConsentedCanonicalTarget(requestingUser, "FACE");

            assertThat(target).isPresent();
            assertThat(target.get().canonicalUserId()).isEqualTo(canonicalUser);
            assertThat(target.get().canonicalTenantId()).isEqualTo(canonicalTenant);
        }

        @Test
        @DisplayName("returns empty (NO signal) when a canonical enrollment exists but consent is NOT granted")
        void noConsentNoSignal() {
            wireIdentityAndCanonical();
            when(consentRepository.findApplicable(identityId, requestingTenant, "FACE"))
                    .thenReturn(List.of()); // default-DENY

            assertThat(service.resolveConsentedCanonicalTarget(requestingUser, "FACE")).isEmpty();
        }

        @Test
        @DisplayName("returns empty (NO signal) when consent row exists but granted=false")
        void revokedNoSignal() {
            wireIdentityAndCanonical();
            IdentityTenantBiometricConsent revoked = IdentityTenantBiometricConsent.builder()
                    .identityId(identityId).tenantId(requestingTenant).method("FACE").build();
            revoked.apply(false);
            when(consentRepository.findApplicable(identityId, requestingTenant, "FACE"))
                    .thenReturn(List.of(revoked));

            assertThat(service.resolveConsentedCanonicalTarget(requestingUser, "FACE")).isEmpty();
        }

        @Test
        @DisplayName("returns empty when the person has NO canonical enrollment elsewhere")
        void noCanonicalNoSignal() {
            when(userRepository.findTenantIdById(requestingUser)).thenReturn(Optional.of(requestingTenant));
            when(userRepository.findIdentityIdById(requestingUser)).thenReturn(Optional.of(identityId));
            when(userRepository.findCanonicalEnrollment(identityId, "FACE", requestingTenant))
                    .thenReturn(List.of());

            assertThat(service.resolveConsentedCanonicalTarget(requestingUser, "FACE")).isEmpty();
            // consent is never even consulted — short-circuits before the gate
            verify(consentRepository, never()).findApplicable(any(), any(), any());
        }

        @Test
        @DisplayName("an all-methods (method=null) granted row authorizes a FACE verify")
        void allMethodsConsentAuthorizesFace() {
            wireIdentityAndCanonical();
            IdentityTenantBiometricConsent allMethods = IdentityTenantBiometricConsent.builder()
                    .identityId(identityId).tenantId(requestingTenant).method(null).build();
            allMethods.apply(true);
            when(consentRepository.findApplicable(identityId, requestingTenant, "FACE"))
                    .thenReturn(List.of(allMethods));

            assertThat(service.resolveConsentedCanonicalTarget(requestingUser, "FACE")).isPresent();
        }
    }
}
