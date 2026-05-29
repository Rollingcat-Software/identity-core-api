package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.TenantProvisioningPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.FlowType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.StepType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.AuthMethodRepository;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Infrastructure adapter that owns the JPA entity wiring for self-service tenant
 * onboarding. Implements {@link TenantProvisioningPort}.
 *
 * <p>This lives in {@code infrastructure.adapter} — one of the packages
 * allow-listed by {@code UserDomainBoundaryTest} to touch {@code entity.User} —
 * so the {@code application}-layer orchestrator
 * ({@link com.fivucsas.identity.application.service.RegisterTenantService}) never
 * has to import the JPA user model.</p>
 *
 * <h2>What it creates (one transaction)</h2>
 * <ol>
 *   <li><b>Tenant</b> — in the requested pending/trial status.</li>
 *   <li><b>Per-tenant TENANT_ADMIN role</b> — permissions cloned from the system
 *       role template ({@value #TEMPLATE_TENANT_ADMIN_ROLE_ID}), mirroring how
 *       V45 keeps existing tenant admin roles in sync.</li>
 *   <li><b>First admin user</b> — TENANT_ADMIN, password already hashed by the
 *       caller, {@code emailVerified=false}, status PENDING_ENROLLMENT, with a
 *       freshly-generated email-verification token; the role is assigned.</li>
 *   <li><b>Primary email-domain claim</b> in {@code tenant_email_domains}.</li>
 *   <li><b>Default APP_LOGIN auth flow</b> — PASSWORD (step 1) + EMAIL_OTP
 *       (step 2), {@code is_default=true, is_active=true}.</li>
 * </ol>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantOnboardingProvisioner implements TenantProvisioningPort {

    /**
     * System role template TENANT_ADMIN role id (V3 seed, under the system
     * tenant {@code 00000000-…}). Its permission set is the canonical baseline
     * copied to every per-tenant TENANT_ADMIN role (kept current by V45).
     */
    static final UUID TEMPLATE_TENANT_ADMIN_ROLE_ID =
            UUID.fromString("20000000-0000-0000-0000-000000000001");

    private static final String TENANT_ADMIN_ROLE_NAME = "TENANT_ADMIN";

    private final JpaTenantRepository tenantRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final AuthMethodRepository authMethodRepository;
    private final AuthFlowRepository authFlowRepository;
    private final TenantEmailDomainRepository tenantEmailDomainRepository;
    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;

    /**
     * Capped seat limit for a self-service TRIAL tenant. Trial tenants are NOT
     * full-production: the cap is lifted only after domain verification /
     * SUPER_ADMIN approval. Configurable via {@code app.onboarding.trial-max-users}.
     */
    @Value("${app.onboarding.trial-max-users:25}")
    private int trialMaxUsers;

    @Override
    @Transactional
    public Result provision(Params params) {
        // ---- 1. Tenant (capped TRIAL — not full production) ---------------
        // maxUsers is held to the trial cap until ownership is verified.
        // biometricEnabled defaults true; mfaRequired/enforceDomainMatching stay
        // OFF (entity defaults) — domain-wide auto-binding requires a VERIFIED
        // domain (V63), which a self-service claim is not yet.
        Tenant tenant = Tenant.builder()
                .name(params.orgName())
                .slug(params.slug())
                .description("Self-service onboarded organisation (trial)")
                .contactEmail(params.adminEmail())
                .status(parseStatus(params.initialStatus()))
                .maxUsers(trialMaxUsers)
                .enforceDomainMatching(false)
                .build();
        tenant = tenantRepository.save(tenant);
        log.info("Onboarding: created tenant {} (slug={}, status={})",
                tenant.getId(), tenant.getSlug(), tenant.getStatus());

        // ---- 2. Per-tenant TENANT_ADMIN role ------------------------------
        Role adminRole = createTenantAdminRole(tenant);

        // ---- 3. First admin user (+ role assignment) ----------------------
        User admin = User.builder()
                .email(params.adminEmail())
                .passwordHash(params.hashedPassword())
                .firstName(params.adminFirstName())
                .lastName(params.adminLastName())
                .tenant(tenant)
                // Email not yet verified → keep the account out of ACTIVE until
                // the admin proves control of the address.
                .status(UserStatus.PENDING_ENROLLMENT)
                .userType(UserType.TENANT_ADMIN)
                .emailVerified(false)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .build();
        String verificationToken = admin.generateEmailVerificationToken();
        User savedAdmin = userRepository.save(admin);

        UserRole assignment = UserRole.create(savedAdmin, adminRole, null);
        userRoleRepository.save(assignment);
        log.info("Onboarding: created admin user {} and assigned TENANT_ADMIN role {}",
                savedAdmin.getId(), adminRole.getId());

        // ---- 4. Claim the primary email domain (UNVERIFIED) ---------------
        // verified=false (3-arg create default, V63): the claim reserves the
        // domain (unique index blocks another tenant taking it) but does NOT
        // auto-bind other registrants until ownership is proven via DNS-TXT
        // (Round 2) or SUPER_ADMIN approval.
        TenantEmailDomain domain = TenantEmailDomain.create(tenant.getId(), params.emailDomain(), true);
        tenantEmailDomainRepository.save(domain);
        log.info("Onboarding: tenant {} claimed primary email domain '{}' (unverified)",
                tenant.getId(), params.emailDomain());

        // ---- 5. Default APP_LOGIN auth flow (PASSWORD + EMAIL_OTP) ---------
        seedDefaultLoginFlow(tenant);

        return new Result(tenant.getId(), savedAdmin.getId(), adminRole.getId(), verificationToken);
    }

    @Override
    @Transactional
    public boolean activateTenantForVerifiedAdmin(UUID adminUserId, boolean requireAdminApproval) {
        Optional<User> maybeAdmin = userRepository.findById(adminUserId);
        if (maybeAdmin.isEmpty()) {
            return false;
        }
        User admin = maybeAdmin.get();
        Tenant tenant = admin.getTenant();
        if (tenant == null) {
            return false;
        }
        // Promote the admin's own account to ACTIVE on verification.
        if (admin.getStatus() == UserStatus.PENDING_ENROLLMENT) {
            admin.setStatus(UserStatus.ACTIVE);
            userRepository.save(admin);
        }

        // Re-load via the JPA repo so we hold a managed entity to flip status on.
        Tenant managed = tenantRepository.findById(tenant.getId()).orElse(null);
        if (managed == null) {
            return false;
        }
        if (managed.getStatus() == TenantStatus.ACTIVE) {
            return true; // idempotent
        }
        if (requireAdminApproval) {
            // Leave PENDING for a SUPER_ADMIN to approve; verification alone is
            // not sufficient under this policy.
            log.info("Onboarding: admin {} verified email but tenant {} stays PENDING "
                    + "(admin approval required)", adminUserId, managed.getId());
            return false;
        }
        managed.activate();
        tenantRepository.save(managed);
        log.info("Onboarding: tenant {} activated after admin {} verified their email",
                managed.getId(), adminUserId);
        return true;
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    private TenantStatus parseStatus(String status) {
        try {
            return TenantStatus.valueOf(status);
        } catch (IllegalArgumentException | NullPointerException e) {
            // Defensive: the caller controls this value, but never default to ACTIVE.
            return TenantStatus.PENDING;
        }
    }

    /**
     * Creates a tenant-scoped TENANT_ADMIN role, copying the permission set from
     * the system role template. If one somehow already exists for this brand-new
     * tenant it is reused (idempotency guard).
     */
    private Role createTenantAdminRole(Tenant tenant) {
        Optional<Role> existing = roleRepository
                .findByTenantIdAndNameAndDeletedAtIsNull(tenant.getId(), TENANT_ADMIN_ROLE_NAME);
        if (existing.isPresent()) {
            return existing.get();
        }

        Set<Permission> permissions = roleRepository
                .findByIdWithPermissions(TEMPLATE_TENANT_ADMIN_ROLE_ID)
                .map(Role::getPermissions)
                .map(HashSet::new)
                .orElseGet(HashSet::new);
        if (permissions.isEmpty()) {
            log.warn("Onboarding: template TENANT_ADMIN role {} has no permissions; "
                    + "the new tenant admin role for {} will start empty",
                    TEMPLATE_TENANT_ADMIN_ROLE_ID, tenant.getId());
        }

        Role role = Role.builder()
                .tenant(tenant)
                .name(TENANT_ADMIN_ROLE_NAME)
                .description("Tenant administrator")
                .isSystemRole(false)
                .active(true)
                .permissions(new HashSet<>(permissions))
                .build();
        return roleRepository.save(role);
    }

    /**
     * Seeds the tenant's default APP_LOGIN auth flow with PASSWORD (step 1) and
     * EMAIL_OTP (step 2). Marked is_default + is_active so it is the flow the
     * hosted-login page resolves for this tenant. Mirrors the V16/V29 seed shape.
     */
    private void seedDefaultLoginFlow(Tenant tenant) {
        AuthMethod password = authMethodRepository.findByType(AuthMethodType.PASSWORD).orElse(null);
        AuthMethod emailOtp = authMethodRepository.findByType(AuthMethodType.EMAIL_OTP).orElse(null);
        if (password == null) {
            // Without the PASSWORD method there is nothing to seed; the global
            // seed (V16) guarantees it exists in any real environment.
            log.warn("Onboarding: PASSWORD auth method missing; skipping default flow seed for tenant {}",
                    tenant.getId());
            return;
        }

        AuthFlow flow = AuthFlow.builder()
                .tenant(tenant)
                .name("Default Login")
                .description("Standard password authentication")
                .flowType(FlowType.AUTHENTICATION)
                .operationType(OperationType.APP_LOGIN)
                .isDefault(true)
                .isActive(true)
                .build();

        AuthFlowStep step1 = AuthFlowStep.builder()
                .authFlow(flow)
                .authMethod(password)
                .stepOrder(1)
                .stepType(StepType.SEQUENTIAL)
                .isRequired(true)
                .timeoutSeconds(120)
                .maxAttempts(3)
                .build();
        flow.getSteps().add(step1);

        if (emailOtp != null) {
            AuthFlowStep step2 = AuthFlowStep.builder()
                    .authFlow(flow)
                    .authMethod(emailOtp)
                    .stepOrder(2)
                    .stepType(StepType.SEQUENTIAL)
                    .isRequired(true)
                    .timeoutSeconds(300)
                    .maxAttempts(3)
                    .build();
            flow.getSteps().add(step2);
        }

        // Cascade.ALL on AuthFlow.steps persists the steps with the flow.
        authFlowRepository.save(flow);
        log.info("Onboarding: seeded default APP_LOGIN flow for tenant {} ({} steps)",
                tenant.getId(), flow.getSteps().size());
    }
}
