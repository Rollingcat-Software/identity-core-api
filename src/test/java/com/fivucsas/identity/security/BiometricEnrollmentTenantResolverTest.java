package com.fivucsas.identity.security;

import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Method;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BiometricEnrollmentTenantResolver} (issue #284). The
 * Hibernate filter path is covered by {@code BiometricEnrollmentTenantResolverIT}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("BiometricEnrollmentTenantResolver")
class BiometricEnrollmentTenantResolverTest {

    private static final UUID TENANT_A = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final UUID TENANT_B = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    @Mock private UserRepository userRepository;
    @Mock private RbacAuthorizationService rbacService;
    @Mock private UserSecurityService userSecurityService;
    @Mock private TenantFilterBypass tenantFilterBypass;

    @InjectMocks private BiometricEnrollmentTenantResolver resolver;

    private final UUID subjectId = UUID.randomUUID();

    @BeforeEach
    void runBypassInline() {
        when(tenantFilterBypass.runWithoutTenantFilter(any()))
                .thenAnswer(inv -> ((Supplier<?>) inv.getArgument(0)).get());
    }

    private void givenSubjectInTenant(UUID tenantId) {
        when(userRepository.findTenantIdById(subjectId)).thenReturn(Optional.ofNullable(tenantId));
        when(userRepository.existsById(subjectId)).thenReturn(true);
    }

    private void givenSubjectMissing() {
        when(userRepository.findTenantIdById(subjectId)).thenReturn(Optional.empty());
        when(userRepository.existsById(subjectId)).thenReturn(false);
    }

    @Test
    void resolve_WhenCallerIsTheSubjectPerPreAuthorizePredicate_ShouldTreatTheEnrollAsSelf() {
        // The caller acts as its tenant-B membership. @PreAuthorize's
        // isCurrentUser (resolved under the active tenant filter) says "self",
        // while the unfiltered oldest-membership lookup names another row whose
        // tenant is A. Self must follow the @PreAuthorize predicate.
        givenSubjectInTenant(TENANT_B);
        when(userSecurityService.isCurrentUser(subjectId)).thenReturn(true);
        when(rbacService.getCurrentUserId()).thenReturn(Optional.of(UUID.randomUUID()));
        when(rbacService.canAccessTenant(TENANT_B)).thenReturn(false);

        assertThat(resolver.resolve(subjectId, null)).isEqualTo(TENANT_B.toString());
    }

    @Test
    void resolve_WhenNonRootCallerNamesUnknownUser_ShouldDenyInsteadOfReporting404() {
        givenSubjectMissing();
        when(rbacService.isRoot()).thenReturn(false);

        assertThatThrownBy(() -> resolver.resolve(subjectId, null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void resolve_WhenRootNamesUnknownUser_ShouldThrowUserNotFound() {
        givenSubjectMissing();
        when(rbacService.isRoot()).thenReturn(true);

        assertThatThrownBy(() -> resolver.resolve(subjectId, null))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void resolve_WhenCallerMayNotActInSubjectsTenant_ShouldDeny() {
        givenSubjectInTenant(TENANT_B);
        when(userSecurityService.isCurrentUser(subjectId)).thenReturn(false);
        when(rbacService.canAccessTenant(TENANT_B)).thenReturn(false);

        assertThatThrownBy(() -> resolver.resolve(subjectId, null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void resolve_WhenRequestedTenantDiffers_ShouldReturnTheSubjectsTenant() {
        givenSubjectInTenant(TENANT_A);
        when(userSecurityService.isCurrentUser(subjectId)).thenReturn(false);
        when(rbacService.canAccessTenant(TENANT_A)).thenReturn(true);

        assertThat(resolver.resolve(subjectId, TENANT_B.toString())).isEqualTo(TENANT_A.toString());
    }

    @Test
    void assertMayEnroll_WhenCallerMayNotActInSubjectsTenant_ShouldDeny() {
        givenSubjectInTenant(TENANT_B);
        when(userSecurityService.isCurrentUser(subjectId)).thenReturn(false);
        when(rbacService.canAccessTenant(TENANT_B)).thenReturn(false);

        assertThatThrownBy(() -> resolver.assertMayEnroll(subjectId))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void publicMethods_WhenInvoked_ShouldRunInAReadOnlyTransaction() throws Exception {
        // TenantFilterBypass requires a transaction; the resolver must open its
        // own instead of relying on open-in-view.
        for (Method m : new Method[] {
                BiometricEnrollmentTenantResolver.class.getMethod("resolve", UUID.class, String.class),
                BiometricEnrollmentTenantResolver.class.getMethod("assertMayEnroll", UUID.class)}) {
            Transactional tx = m.getAnnotation(Transactional.class);
            assertThat(tx).as(m.getName() + " must be @Transactional").isNotNull();
            assertThat(tx.readOnly()).as(m.getName() + " must be read-only").isTrue();
        }
    }
}
