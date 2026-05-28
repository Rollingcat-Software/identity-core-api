package com.fivucsas.identity.application.service.verification;

import com.fivucsas.identity.application.service.ManageVerificationService;
import com.fivucsas.identity.domain.model.auth.FlowType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.repository.*;
import com.fivucsas.identity.security.TenantScopeResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * S2 (verification-session object-level IDOR) regression tests for
 * {@link ManageVerificationService}.
 *
 * <p>Before the fix, {@code POST /api/v1/verification/sessions} had no
 * {@code @PreAuthorize} and passed the client-supplied {@code userId} /
 * {@code tenantId} straight through, and the read/complete paths did no
 * object-level check — so any authenticated caller could create, read, or
 * complete a verification session for any user in any tenant.</p>
 *
 * <p>The service now consults {@link TenantScopeResolver#canAccessTenant(UUID)}
 * (admin-on-behalf model). {@code canAccessTenant} returns {@code true} for
 * SUPER_ADMIN / ROOT (null scope ⇒ {@code isUnrestricted()} true), so ROOT keeps
 * cross-tenant access while everyone else is confined to their own tenant. An
 * out-of-scope caller is rejected with {@link AccessDeniedException} (→ HTTP 403
 * via {@code GlobalExceptionHandler}) BEFORE anything is persisted. Mirrors
 * {@code ManageTenantServiceUpdateScopeTest} (S1).</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ManageVerificationService — object-level authz (S2)")
class ManageVerificationServiceScopeTest {

    @Mock private VerificationSessionRepository sessionRepository;
    @Mock private VerificationStepResultRepository stepResultRepository;
    @Mock private VerificationDocumentRepository documentRepository;
    @Mock private AuthFlowRepository authFlowRepository;
    @Mock private UserRepository userRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private VerificationStepHandlerRegistry handlerRegistry;
    @Spy private ObjectMapper objectMapper = new ObjectMapper();
    @Mock private TenantScopeResolver tenantScopeResolver;

    @InjectMocks
    private ManageVerificationService service;

    private final UUID userId = UUID.randomUUID();
    private final UUID tenantId = UUID.randomUUID();
    private final UUID otherTenantId = UUID.randomUUID();
    private final UUID flowId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();

    // ---------------------------------------------------------------- createSession

    @Test
    @DisplayName("createSession: out-of-scope tenant → AccessDenied, nothing persisted")
    void createSession_outOfScopeTenant_throwsAndDoesNotPersist() {
        // Caller is NOT in scope for the requested tenant id.
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(false);

        assertThatThrownBy(() -> service.createSession(userId, tenantId, flowId))
                .isInstanceOf(AccessDeniedException.class);

        // Guard runs before any load or save.
        verify(userRepository, never()).findById(any(UUID.class));
        verify(tenantRepository, never()).findById(any(UUID.class));
        verify(sessionRepository, never()).save(any(VerificationSession.class));
    }

    @Test
    @DisplayName("createSession: in-scope tenant but user belongs to a DIFFERENT tenant → AccessDenied, nothing persisted")
    void createSession_userBelongsToDifferentTenant_throwsAndDoesNotPersist() {
        // Tenant is in scope, caller is restricted (not ROOT), but the target
        // user actually belongs to another tenant.
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(true);
        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(otherTenantId));

        assertThatThrownBy(() -> service.createSession(userId, tenantId, flowId))
                .isInstanceOf(AccessDeniedException.class);

        verify(sessionRepository, never()).save(any(VerificationSession.class));
    }

    @Test
    @DisplayName("createSession: in-scope admin creating for a user of THEIR tenant succeeds")
    void createSession_inScopeAdmin_succeeds() {
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(true);
        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

        stubHappyPathCreate();

        assertThat(service.createSession(userId, tenantId, flowId)).isNotNull();
        verify(sessionRepository).save(any(VerificationSession.class));
    }

    @Test
    @DisplayName("createSession: ROOT (unrestricted) may create cross-tenant without ownership re-check")
    void createSession_rootCrossTenant_succeeds() {
        // Root: canAccessTenant true for any tenant; isUnrestricted true skips the
        // user-ownership re-check, so findTenantIdById is never consulted.
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(true);
        when(tenantScopeResolver.isUnrestricted()).thenReturn(true);

        stubHappyPathCreate();

        assertThat(service.createSession(userId, tenantId, flowId)).isNotNull();
        verify(userRepository, never()).findTenantIdById(any(UUID.class));
        verify(sessionRepository).save(any(VerificationSession.class));
    }

    private void stubHappyPathCreate() {
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        AuthFlow flow = mock(AuthFlow.class);
        when(flow.getFlowType()).thenReturn(FlowType.VERIFICATION);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));

        VerificationSession saved = mock(VerificationSession.class);
        when(saved.getId()).thenReturn(sessionId);
        when(saved.getUser()).thenReturn(user);
        when(saved.getTenant()).thenReturn(tenant);
        when(saved.getFlow()).thenReturn(flow);
        when(saved.getStatus()).thenReturn(com.fivucsas.identity.domain.model.auth.VerificationSessionStatus.PENDING);
        when(saved.getCurrentStepNumber()).thenReturn(0);
        when(saved.getStepResults()).thenReturn(null);
        when(user.getId()).thenReturn(userId);
        when(tenant.getId()).thenReturn(tenantId);
        when(flow.getId()).thenReturn(flowId);
        when(flow.getName()).thenReturn("KYC");
        when(sessionRepository.save(any(VerificationSession.class))).thenReturn(saved);
    }

    // ---------------------------------------------------------------- getSession

    @Test
    @DisplayName("getSession: session of another tenant → AccessDenied")
    void getSession_outOfScopeSession_throws() {
        VerificationSession session = mock(VerificationSession.class);
        Tenant sessionTenant = mock(Tenant.class);
        when(sessionTenant.getId()).thenReturn(otherTenantId);
        when(session.getTenant()).thenReturn(sessionTenant);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(tenantScopeResolver.canAccessTenant(otherTenantId)).thenReturn(false);

        assertThatThrownBy(() -> service.getSession(sessionId))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("getSession: in-scope session succeeds")
    void getSession_inScopeSession_succeeds() {
        VerificationSession session = mock(VerificationSession.class);
        Tenant sessionTenant = mock(Tenant.class);
        when(sessionTenant.getId()).thenReturn(tenantId);
        when(session.getTenant()).thenReturn(sessionTenant);
        // Stubs required only for VerificationSessionResponse.from(session).
        User user = mock(User.class);
        AuthFlow flow = mock(AuthFlow.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(session.getFlow()).thenReturn(flow);
        when(session.getStatus()).thenReturn(com.fivucsas.identity.domain.model.auth.VerificationSessionStatus.PENDING);
        when(session.getStepResults()).thenReturn(null);
        when(user.getId()).thenReturn(userId);
        when(flow.getId()).thenReturn(flowId);
        when(flow.getName()).thenReturn("KYC");
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(true);

        assertThat(service.getSession(sessionId)).isNotNull();
    }

    @Test
    @DisplayName("getSession: ROOT (unrestricted) may read cross-tenant session")
    void getSession_rootCrossTenant_succeeds() {
        VerificationSession session = mock(VerificationSession.class);
        Tenant sessionTenant = mock(Tenant.class);
        User user = mock(User.class);
        AuthFlow flow = mock(AuthFlow.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(session.getTenant()).thenReturn(sessionTenant);
        when(session.getFlow()).thenReturn(flow);
        when(session.getStatus()).thenReturn(com.fivucsas.identity.domain.model.auth.VerificationSessionStatus.PENDING);
        when(session.getStepResults()).thenReturn(null);
        when(user.getId()).thenReturn(userId);
        when(sessionTenant.getId()).thenReturn(otherTenantId);
        when(flow.getId()).thenReturn(flowId);
        when(flow.getName()).thenReturn("KYC");
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        when(tenantScopeResolver.isUnrestricted()).thenReturn(true);

        assertThat(service.getSession(sessionId)).isNotNull();
        // Unrestricted short-circuits before canAccessTenant is consulted.
        verify(tenantScopeResolver, never()).canAccessTenant(any(UUID.class));
    }

    // ---------------------------------------------------------------- completeSession

    @Test
    @DisplayName("completeSession: session of another tenant → AccessDenied, not marked completed")
    void completeSession_outOfScopeSession_throws() {
        VerificationSession session = mock(VerificationSession.class);
        Tenant sessionTenant = mock(Tenant.class);
        when(sessionTenant.getId()).thenReturn(otherTenantId);
        when(session.getTenant()).thenReturn(sessionTenant);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(tenantScopeResolver.canAccessTenant(otherTenantId)).thenReturn(false);

        assertThatThrownBy(() -> service.completeSession(sessionId))
                .isInstanceOf(AccessDeniedException.class);

        verify(session, never()).markCompleted();
        verify(sessionRepository, never()).save(any(VerificationSession.class));
    }

    // ---------------------------------------------------------------- getUserVerificationStatus

    @Test
    @DisplayName("getUserVerificationStatus: target user of another tenant → AccessDenied")
    void getUserVerificationStatus_outOfScopeUser_throws() {
        when(tenantScopeResolver.isUnrestricted()).thenReturn(false);
        when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(otherTenantId));
        when(tenantScopeResolver.canAccessTenant(otherTenantId)).thenReturn(false);

        assertThatThrownBy(() -> service.getUserVerificationStatus(userId))
                .isInstanceOf(AccessDeniedException.class);

        // The full user aggregate is never loaded once the guard fails.
        verify(userRepository, never()).findById(any(UUID.class));
    }
}
