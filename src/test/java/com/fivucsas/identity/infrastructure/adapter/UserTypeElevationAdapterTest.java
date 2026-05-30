package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserTypeElevationAdapter} — the elevate-on-grant tier
 * sync (role / user_type unification, docs/IDENTITY_ROLE_UNIFICATION.md).
 *
 * <p>Asserts: granting the ROOT role elevates user_type to ROOT; granting a
 * TENANT_ADMIN role elevates to TENANT_ADMIN; a plain permission role does not
 * change the tier; and the sync is ELEVATE-ONLY (granting a lower-tier role
 * never demotes a higher existing tier).</p>
 */
@ExtendWith(MockitoExtension.class)
class UserTypeElevationAdapterTest {

    @Mock private UserRepository userRepository;
    @InjectMocks private UserTypeElevationAdapter adapter;

    private static final UUID ROOT_ROLE_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000001");

    private User userWithType(UserType type) {
        return User.builder().id(UUID.randomUUID()).email("u@example.com").userType(type).build();
    }

    @Test
    @DisplayName("granting ROOT role → user_type elevated to ROOT")
    void grantRootRoleElevatesToRoot() {
        User user = userWithType(UserType.TENANT_ADMIN);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        adapter.elevateForGrantedRole(user.getId(), ROOT_ROLE_ID, "ROOT");

        assertThat(user.getUserType()).isEqualTo(UserType.ROOT);
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("granting ROOT role matched by NAME (any id) → ROOT")
    void grantRootRoleByNameElevatesToRoot() {
        User user = userWithType(UserType.TENANT_MEMBER);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        adapter.elevateForGrantedRole(user.getId(), UUID.randomUUID(), "ROOT");

        assertThat(user.getUserType()).isEqualTo(UserType.ROOT);
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("granting a per-tenant TENANT_ADMIN role → user_type elevated to TENANT_ADMIN")
    void grantTenantAdminRoleElevatesToTenantAdmin() {
        User user = userWithType(UserType.TENANT_MEMBER);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        // A per-tenant TENANT_ADMIN role has its own random id, matched by name.
        adapter.elevateForGrantedRole(user.getId(), UUID.randomUUID(), "TENANT_ADMIN");

        assertThat(user.getUserType()).isEqualTo(UserType.TENANT_ADMIN);
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("granting a plain permission role → user_type unchanged (no save)")
    void grantPlainRoleDoesNotChangeTier() {
        User user = userWithType(UserType.TENANT_MEMBER);

        adapter.elevateForGrantedRole(user.getId(), UUID.randomUUID(), "ENROLLMENT_MANAGER");

        assertThat(user.getUserType()).isEqualTo(UserType.TENANT_MEMBER);
        // Plain role never resolves a tier — we don't even load the user.
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("ELEVATE-ONLY: granting TENANT_ADMIN to a ROOT user does NOT demote")
    void grantTenantAdminToRootDoesNotDemote() {
        User user = userWithType(UserType.ROOT);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        adapter.elevateForGrantedRole(user.getId(), UUID.randomUUID(), "TENANT_ADMIN");

        assertThat(user.getUserType()).isEqualTo(UserType.ROOT);
        verify(userRepository, never()).save(any());
    }
}
