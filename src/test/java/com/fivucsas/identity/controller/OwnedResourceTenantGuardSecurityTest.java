package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ChangePasswordUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.application.port.output.UserSettingsRepositoryPort;
import com.fivucsas.identity.application.port.output.UserTenantPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.application.service.GuestLifecycleService;
import com.fivucsas.identity.application.service.ManageDeviceService;
import com.fivucsas.identity.application.service.UsernamelessLoginFlowService;
import com.fivucsas.identity.application.service.WebAuthnCredentialService;
import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.exception.GlobalExceptionHandler;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.RbacPermissionEvaluator;
import com.fivucsas.identity.security.TenantScopeResolver;
import com.fivucsas.identity.security.UserSecurityService;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Endpoints that name a user-owned or tenant-owned resource by its own id (a passkey,
 * a device, a guest invitation) rather than by a user id, with the REAL method-security
 * wiring and the REAL application services behind them.
 *
 * <p>PF-5 closes the class "a resource of tenant B is reachable by a caller of tenant
 * A". These endpoints were outside the first pass because their path carries no user
 * id: the services loaded the row with {@code findById} (which ignores the Hibernate
 * {@code tenantFilter}) and acted on it with no owner or tenant check. A refused
 * caller gets 404, never 403, so the response does not reveal that the id exists.</p>
 */
@SpringJUnitConfig(OwnedResourceTenantGuardSecurityTest.Config.class)
@DisplayName("Resources named by their own id: owner or same-tenant admin only")
class OwnedResourceTenantGuardSecurityTest {

    static final UUID TENANT_A = UUID.fromString("0a0a0a0a-0000-4000-8000-00000000000a");
    static final UUID TENANT_B = UUID.fromString("0b0b0b0b-0000-4000-8000-00000000000b");
    static final UUID USER_IN_A = UUID.fromString("1a1a1a1a-0000-4000-8000-00000000001a");
    static final UUID OTHER_USER_IN_A = UUID.fromString("2a2a2a2a-0000-4000-8000-00000000002a");
    static final UUID USER_IN_B = UUID.fromString("1b1b1b1b-0000-4000-8000-00000000001b");

    static final UUID CREDENTIAL_OF_A = UUID.fromString("ca000000-0000-4000-8000-0000000000ca");
    static final UUID CREDENTIAL_OF_B = UUID.fromString("cb000000-0000-4000-8000-0000000000cb");
    static final UUID DEVICE_OF_A = UUID.fromString("da000000-0000-4000-8000-0000000000da");
    static final UUID DEVICE_OF_B = UUID.fromString("db000000-0000-4000-8000-0000000000db");
    static final UUID INVITATION_OF_A = UUID.fromString("ea000000-0000-4000-8000-0000000000ea");
    static final UUID INVITATION_OF_B = UUID.fromString("eb000000-0000-4000-8000-0000000000eb");

    // @TestConfiguration keeps this nested config out of component scanning of the
    // @SpringBootTest contexts (see TenantAuthMethodSecurityTest for the history).
    @TestConfiguration
    @EnableMethodSecurity
    @Import({DeviceController.class, UserController.class, ManageDeviceService.class,
            WebAuthnCredentialService.class, TenantScopeResolver.class})
    static class Config {
        // Shared by the RBAC service and UserController.
        @Bean UserRepository userRepository() { return mock(UserRepository.class); }
        @Bean RoleRepository roleRepository() { return mock(RoleRepository.class); }
        @Bean JpaTenantRepository jpaTenantRepository() { return mock(JpaTenantRepository.class); }

        // ManageDeviceService
        @Bean UserDeviceRepositoryPort userDeviceRepositoryPort() { return mock(UserDeviceRepositoryPort.class); }
        @Bean com.fivucsas.identity.domain.repository.UserRepository domainUserRepository() {
            return mock(com.fivucsas.identity.domain.repository.UserRepository.class);
        }
        @Bean UserTenantPort userTenantPort() { return mock(UserTenantPort.class); }

        // WebAuthnCredentialService
        @Bean WebAuthnCredentialRepositoryPort webAuthnCredentialRepositoryPort() {
            return mock(WebAuthnCredentialRepositoryPort.class);
        }
        @Bean ManageEnrollmentUseCase manageEnrollmentUseCase() { return mock(ManageEnrollmentUseCase.class); }

        // DeviceController collaborators these endpoints do not use
        @Bean WebAuthnService webAuthnService() { return mock(WebAuthnService.class); }
        @Bean TokenGenerationPort tokenGenerationPort() { return mock(TokenGenerationPort.class); }
        @Bean RefreshTokenService refreshTokenService() { return mock(RefreshTokenService.class); }
        @Bean UsernamelessLoginFlowService usernamelessLoginFlowService() {
            return mock(UsernamelessLoginFlowService.class);
        }

        // UserController collaborators
        @Bean ManageUserUseCase manageUserUseCase() { return mock(ManageUserUseCase.class); }
        @Bean ChangePasswordUseCase changePasswordUseCase() { return mock(ChangePasswordUseCase.class); }
        @Bean UserSettingsRepositoryPort userSettingsRepositoryPort() { return mock(UserSettingsRepositoryPort.class); }
        @Bean GuestLifecycleService guestLifecycleService() { return mock(GuestLifecycleService.class); }
        @Bean GuestInvitationRepositoryPort guestInvitationRepositoryPort() {
            return mock(GuestInvitationRepositoryPort.class);
        }

        @Bean
        @SuppressWarnings("unchecked")
        TenantFilterBypass tenantFilterBypass() {
            TenantFilterBypass bypass = mock(TenantFilterBypass.class);
            when(bypass.runWithoutTenantFilter(any())).thenAnswer(inv -> ((Supplier<Object>) inv.getArgument(0)).get());
            return bypass;
        }

        @Bean(name = "rbac")
        RbacAuthorizationService rbac(UserRepository users, RoleRepository roles, TenantFilterBypass bypass) {
            return new RbacAuthorizationService(users, roles, bypass);
        }

        @Bean(name = "userSecurityService")
        UserSecurityService userSecurityService(UserRepository users) {
            return new UserSecurityService(users);
        }

        @Bean
        MethodSecurityExpressionHandler methodSecurityExpressionHandler(RbacAuthorizationService rbac) {
            DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
            handler.setPermissionEvaluator(new RbacPermissionEvaluator(rbac));
            return handler;
        }
    }

    @Autowired DeviceController deviceController;
    @Autowired UserController userController;
    @Autowired UserRepository userRepository;
    @Autowired com.fivucsas.identity.domain.repository.UserRepository domainUserRepository;
    @Autowired JpaTenantRepository tenantRepository;
    @Autowired UserTenantPort userTenantPort;
    @Autowired WebAuthnCredentialRepositoryPort credentialRepository;
    @Autowired UserDeviceRepositoryPort deviceRepository;
    @Autowired GuestInvitationRepositoryPort invitationRepository;
    @Autowired GuestLifecycleService guestLifecycleService;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        Mockito.reset(userRepository, domainUserRepository, tenantRepository, userTenantPort,
                credentialRepository, deviceRepository, invitationRepository, guestLifecycleService);

        User memberA = user(USER_IN_A, "member-a@example.test", UserType.TENANT_MEMBER, TENANT_A);
        User otherMemberA = user(OTHER_USER_IN_A, "member2-a@example.test", UserType.TENANT_MEMBER, TENANT_A);
        User memberB = user(USER_IN_B, "member-b@example.test", UserType.TENANT_MEMBER, TENANT_B);
        when(userRepository.findById(USER_IN_A)).thenReturn(Optional.of(memberA));
        when(userRepository.findById(OTHER_USER_IN_A)).thenReturn(Optional.of(otherMemberA));
        when(userRepository.findById(USER_IN_B)).thenReturn(Optional.of(memberB));
        when(domainUserRepository.findById(USER_IN_A)).thenReturn(Optional.of(memberA));
        when(domainUserRepository.findById(USER_IN_B)).thenReturn(Optional.of(memberB));
        when(userTenantPort.findTenantIdOfUser(USER_IN_A)).thenReturn(Optional.of(TENANT_A));
        when(userTenantPort.findTenantIdOfUser(USER_IN_B)).thenReturn(Optional.of(TENANT_B));
        when(tenantRepository.findById(TENANT_A)).thenReturn(Optional.of(tenant(TENANT_A)));
        when(tenantRepository.findById(TENANT_B)).thenReturn(Optional.of(tenant(TENANT_B)));

        when(credentialRepository.findById(CREDENTIAL_OF_A)).thenReturn(Optional.of(credential(CREDENTIAL_OF_A, "cred-a", memberA)));
        when(credentialRepository.findById(CREDENTIAL_OF_B)).thenReturn(Optional.of(credential(CREDENTIAL_OF_B, "cred-b", memberB)));
        when(credentialRepository.findByCredentialId("cred-a")).thenReturn(Optional.of(credential(CREDENTIAL_OF_A, "cred-a", memberA)));
        when(credentialRepository.findByCredentialId("cred-b")).thenReturn(Optional.of(credential(CREDENTIAL_OF_B, "cred-b", memberB)));
        when(credentialRepository.findAllByUserId(any())).thenReturn(List.of());

        when(deviceRepository.findById(DEVICE_OF_A)).thenReturn(Optional.of(device(DEVICE_OF_A, memberA)));
        when(deviceRepository.findById(DEVICE_OF_B)).thenReturn(Optional.of(device(DEVICE_OF_B, memberB)));
        when(deviceRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        when(invitationRepository.findById(INVITATION_OF_A)).thenReturn(Optional.of(invitation(INVITATION_OF_A, TENANT_A)));
        when(invitationRepository.findById(INVITATION_OF_B)).thenReturn(Optional.of(invitation(INVITATION_OF_B, TENANT_B)));

        mvc = MockMvcBuilders.standaloneSetup(deviceController, userController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static Tenant tenant(UUID id) {
        return Tenant.builder().id(id).name("t").build();
    }

    private static User user(UUID id, String email, UserType type, UUID tenantId) {
        return User.builder()
                .id(id)
                .email(email)
                .userType(type)
                .tenant(tenantId == null ? null : tenant(tenantId))
                .build();
    }

    private static WebAuthnCredential credential(UUID id, String credentialId, User owner) {
        return WebAuthnCredential.builder().id(id).credentialId(credentialId).user(owner).transports("internal").build();
    }

    private static UserDevice device(UUID id, User owner) {
        return UserDevice.builder().id(id).user(owner).tenant(owner.getTenant())
                .deviceFingerprint("fp-" + id).platform(DevicePlatform.ANDROID).build();
    }

    private static GuestInvitation invitation(UUID id, UUID tenantId) {
        return GuestInvitation.builder().id(id).tenant(tenant(tenantId)).email("guest@example.test").build();
    }

    private void signedInAs(UUID id, String email, UserType type, UUID tenantId) {
        User caller = user(id, email, type, tenantId);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(caller));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(email, "n/a", List.of()));
    }

    private void signedInAsMemberOfA() {
        signedInAs(USER_IN_A, "member-a@example.test", UserType.TENANT_MEMBER, TENANT_A);
    }

    private void signedInAsTenantAdminOfA() {
        signedInAs(UUID.randomUUID(), "admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);
    }

    private void signedInAsRoot() {
        signedInAs(UUID.randomUUID(), "root@example.test", UserType.ROOT, null);
    }

    @Nested
    @DisplayName("DELETE /api/v1/webauthn/credentials/by-id/{id}")
    class DeleteCredentialById {

        @Test
        void deleteById_WhenMemberOfAnotherTenant_ShouldReturn404AndKeepTheCredential() throws Exception {
            signedInAsMemberOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/by-id/{id}", CREDENTIAL_OF_B))
                    .andExpect(status().isNotFound());
            verify(credentialRepository, never()).deleteById(any());
        }

        @Test
        void deleteById_WhenAdminOfAnotherTenant_ShouldReturn404AndKeepTheCredential() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/by-id/{id}", CREDENTIAL_OF_B))
                    .andExpect(status().isNotFound());
            verify(credentialRepository, never()).deleteById(any());
        }

        @Test
        void deleteById_WhenOtherMemberOfSameTenantWithoutPermission_ShouldReturn404() throws Exception {
            signedInAs(OTHER_USER_IN_A, "member2-a@example.test", UserType.TENANT_MEMBER, TENANT_A);

            mvc.perform(delete("/api/v1/webauthn/credentials/by-id/{id}", CREDENTIAL_OF_A))
                    .andExpect(status().isNotFound());
            verify(credentialRepository, never()).deleteById(any());
        }

        @Test
        void deleteById_WhenOwner_ShouldReturn204() throws Exception {
            signedInAsMemberOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/by-id/{id}", CREDENTIAL_OF_A))
                    .andExpect(status().isNoContent());
            verify(credentialRepository).deleteById(CREDENTIAL_OF_A);
        }

        @Test
        void deleteById_WhenAdminOfSameTenant_ShouldReturn204() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/by-id/{id}", CREDENTIAL_OF_A))
                    .andExpect(status().isNoContent());
            verify(credentialRepository).deleteById(CREDENTIAL_OF_A);
        }

        @Test
        void deleteById_WhenRoot_ShouldReturn204ForAnyTenant() throws Exception {
            signedInAsRoot();

            mvc.perform(delete("/api/v1/webauthn/credentials/by-id/{id}", CREDENTIAL_OF_B))
                    .andExpect(status().isNoContent());
            verify(credentialRepository).deleteById(CREDENTIAL_OF_B);
        }
    }

    @Nested
    @DisplayName("DELETE /api/v1/webauthn/credentials/{credentialId}")
    class DeleteCredentialByCredentialId {

        @Test
        void deleteByCredentialId_WhenAdminOfAnotherTenant_ShouldReturn404AndKeepTheCredential() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/{credentialId}", "cred-b"))
                    .andExpect(status().isNotFound());
            verify(credentialRepository, never()).deleteByCredentialId(anyString());
        }

        @Test
        void deleteByCredentialId_WhenMemberOfAnotherTenant_ShouldReturn404AndKeepTheCredential() throws Exception {
            signedInAsMemberOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/{credentialId}", "cred-b"))
                    .andExpect(status().isNotFound());
            verify(credentialRepository, never()).deleteByCredentialId(anyString());
        }

        @Test
        void deleteByCredentialId_WhenOwner_ShouldReturn204() throws Exception {
            signedInAsMemberOfA();

            mvc.perform(delete("/api/v1/webauthn/credentials/{credentialId}", "cred-a"))
                    .andExpect(status().isNoContent());
            verify(credentialRepository).deleteByCredentialId("cred-a");
        }
    }

    @Nested
    @DisplayName("DELETE /api/v1/devices/{deviceId}")
    class RemoveDevice {

        @Test
        void removeDevice_WhenAdminOfAnotherTenant_ShouldReturn404AndKeepTheDevice() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/devices/{id}", DEVICE_OF_B))
                    .andExpect(status().isNotFound());
            verify(deviceRepository, never()).delete(any());
        }

        @Test
        void removeDevice_WhenAdminOfSameTenant_ShouldReturn204() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(delete("/api/v1/devices/{id}", DEVICE_OF_A))
                    .andExpect(status().isNoContent());
            verify(deviceRepository).delete(any());
        }

        @Test
        void removeDevice_WhenRoot_ShouldReturn204ForAnyTenant() throws Exception {
            signedInAsRoot();

            mvc.perform(delete("/api/v1/devices/{id}", DEVICE_OF_B))
                    .andExpect(status().isNoContent());
            verify(deviceRepository).delete(any());
        }
    }

    @Nested
    @DisplayName("POST /api/v1/devices")
    class RegisterDevice {

        private static final String BODY = "{\"deviceName\":\"phone\",\"platform\":\"ANDROID\",\"deviceFingerprint\":\"fp-1\"}";

        @Test
        void registerDevice_WhenRootPassesTenantOtherThanTheUsers_ShouldReturn400AndWriteNothing() throws Exception {
            signedInAsRoot();

            mvc.perform(post("/api/v1/devices")
                            .param("userId", USER_IN_B.toString())
                            .param("tenantId", TENANT_A.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(BODY))
                    .andExpect(status().isBadRequest());
            verify(deviceRepository, never()).save(any());
        }

        @Test
        void registerDevice_WhenRootPassesTheUsersTenant_ShouldReturn201() throws Exception {
            signedInAsRoot();

            mvc.perform(post("/api/v1/devices")
                            .param("userId", USER_IN_B.toString())
                            .param("tenantId", TENANT_B.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(BODY))
                    .andExpect(status().isCreated());
            verify(deviceRepository).save(any());
        }
    }

    @Nested
    @DisplayName("POST /api/v1/guests/{invitationId}/resend")
    class ResendInvitation {

        @Test
        void resendInvitation_WhenAdminOfAnotherTenant_ShouldReturn404AndSendNothing() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/guests/{id}/resend", INVITATION_OF_B))
                    .andExpect(status().isNotFound());
            verify(guestLifecycleService, never()).resendInvitation(any());
        }

        @Test
        void resendInvitation_WhenInvitationUnknown_ShouldReturn404AndSendNothing() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/guests/{id}/resend", UUID.randomUUID()))
                    .andExpect(status().isNotFound());
            verify(guestLifecycleService, never()).resendInvitation(any());
        }

        @Test
        void resendInvitation_WhenAdminOfSameTenant_ShouldReturn204() throws Exception {
            signedInAsTenantAdminOfA();

            mvc.perform(post("/api/v1/guests/{id}/resend", INVITATION_OF_A))
                    .andExpect(status().isNoContent());
            verify(guestLifecycleService).resendInvitation(INVITATION_OF_A);
        }

        @Test
        void resendInvitation_WhenRoot_ShouldReturn204ForAnyTenant() throws Exception {
            signedInAsRoot();

            mvc.perform(post("/api/v1/guests/{id}/resend", INVITATION_OF_B))
                    .andExpect(status().isNoContent());
            verify(guestLifecycleService).resendInvitation(INVITATION_OF_B);
        }
    }
}
