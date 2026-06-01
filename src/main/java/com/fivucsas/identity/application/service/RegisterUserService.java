package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.RegisterUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.TenantUserQuotaExceededException;
import com.fivucsas.identity.domain.model.user.Email;
import com.fivucsas.identity.domain.model.user.FullName;
import com.fivucsas.identity.domain.model.user.HashedPassword;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for user registration.
 *
 * Implements the RegisterUserUseCase input port.
 * This is the application layer coordinating the registration flow.
 *
 * Following principles:
 * - Single Responsibility: Only handles user registration logic
 * - Dependency Inversion: Depends on ports (interfaces), not implementations
 * - Open/Closed: New features added via new services
 * - Hexagonal Architecture: Application service coordinates domain and infrastructure
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterUserService implements RegisterUserUseCase {

    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;
    private final TenantEmailDomainRepository tenantEmailDomainRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;
    private final com.fivucsas.identity.infrastructure.otp.OtpService otpService;
    private final com.fivucsas.identity.infrastructure.email.EmailService emailService;
    private final com.fivucsas.identity.application.port.output.MemberRoleAssignmentPort memberRoleAssignmentPort;

    @Value("${app.default-tenant-slug:default}")
    private String defaultTenantSlug;

    @Override
    @Transactional
    public AuthenticationResponse execute(RegisterUserCommand command) {
        log.info("Registering new user: {}", command.getEmail());

        // Validate email uniqueness
        if (userRepository.existsByEmail(command.getEmail())) {
            throw new DuplicateEmailException(command.getEmail());
        }

        // Validate inputs using value objects
        Email email = Email.of(command.getEmail());
        FullName fullName = FullName.of(command.getFirstName(), command.getLastName());

        // Resolve tenant. Order of precedence:
        //   1. Explicit TenantContext (e.g. invitation flow, multi-tenant header).
        //   2. tenant_email_domains (V44) — multi-domain lookup keyed on the
        //      domain part of the user's email; this is the canonical path.
        //   3. Legacy tenants.domain column — single-domain fall-back during
        //      V44 rollout so tenants whose admin has not yet migrated to
        //      tenant_email_domains continue to resolve correctly.
        //   4. Explicit "default" tenant (configurable slug) — opt-in catch-all
        //      that an operator must deliberately provision.
        // FAIL-CLOSED (security fix): if NONE of the above resolves, registration
        // is REJECTED. The previous final fallback —
        // tenantRepository.findAll().stream().findFirst() — silently dropped an
        // unmatched-domain self-registration into an ARBITRARY real tenant
        // (whichever row sorted first; a red-team registered into "Marmara
        // University" this way). An open self-registration must never join a
        // tenant it cannot be matched to; the caller must use a matched domain or
        // an explicit tenant/clientId (TenantContext).
        // Tracks whether the tenant was AUTO-BOUND from a VERIFIED email domain
        // (V63/V64). Only that path triggers default-role-on-join — an explicit
        // tenant context (invitation/header) or the default-tenant fallback do
        // not auto-provision a member role.
        boolean[] autoBoundViaVerifiedDomain = {false};
        Tenant defaultTenant;
        java.util.UUID contextTenantId = com.fivucsas.identity.infrastructure.multitenancy.TenantContext.getCurrentTenant();
        if (contextTenantId != null) {
            defaultTenant = tenantRepository.findById(contextTenantId)
                .orElseThrow(() -> new com.fivucsas.identity.domain.exception.TenantNotFoundException(contextTenantId.toString()));
        } else {
            defaultTenant = resolveTenantByEmailDomain(email.getDomain(), autoBoundViaVerifiedDomain)
                .or(() -> tenantRepository.findBySlug(defaultTenantSlug))
                .orElseThrow(() -> {
                    log.warn("AUDIT: Registration refused — no tenant context, no email-domain match for '{}', "
                            + "and no '{}' catch-all tenant. Self-registration will NOT join an arbitrary tenant.",
                        email.getDomain(), defaultTenantSlug);
                    return new com.fivucsas.identity.domain.exception.EmailDomainNotAllowedException(
                        email.getDomain());
                });
        }

        // V62 — opt-in email-domain enforcement. When the resolved/targeted
        // tenant has enforce_domain_matching=true, the registrant's email
        // domain MUST be present in that tenant's tenant_email_domains registry
        // (V44). On a miss we reject outright rather than silently letting the
        // user through (when enforcement is OFF the resolution above already
        // either auto-bound on a match or fell through to the default tenant —
        // that graceful path is preserved). Checked BEFORE the bcrypt hash so a
        // rejected registration doesn't pay for a hashing round.
        //
        // Note: a domain belongs to at most ONE tenant (ux_tenant_email_domains_domain),
        // so we scope the membership check to the resolved tenant's id — a
        // domain owned by a DIFFERENT tenant must not satisfy this tenant's gate.
        if (defaultTenant.isEnforceDomainMatching()) {
            String emailDomain = email.getDomain();
            // Only VERIFIED domains (V63) satisfy the gate — a self-service tenant's
            // unverified claim must not let arbitrary registrants in.
            boolean domainAllowed = emailDomain != null
                && tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue(emailDomain)
                    .map(TenantEmailDomain::getTenantId)
                    .filter(ownerTenantId -> ownerTenantId.equals(defaultTenant.getId()))
                    .isPresent();
            if (!domainAllowed) {
                log.warn("AUDIT: Registration refused — email domain '{}' not allowed for "
                        + "tenant {} (enforce_domain_matching=true)", emailDomain, defaultTenant.getId());
                throw new com.fivucsas.identity.domain.exception.EmailDomainNotAllowedException(emailDomain);
            }
        }

        // P0-#7 (INVESTIGATION_MASTER_2026-05-07): enforce tenant.max_users
        // BEFORE inserting (and before bcrypt-hashing the password — saves a
        // CPU-bound round on the rejected path). The field defaulted to 100
        // and was admin-editable but had ZERO insert-path readers — every
        // tenant could grow beyond its license unchecked. countByTenantId is
        // a single COUNT query; any race where two concurrent registrations
        // land on N == max_users will be caught by the next attempt (we
        // check >= so we never silently exceed by more than one within the
        // same transaction window).
        long currentUserCount = userRepository.countByTenantId(defaultTenant.getId());
        if (currentUserCount >= defaultTenant.getMaxUsers()) {
            log.warn("AUDIT: Registration refused — tenant quota exceeded, tenantId={}, currentUsers={}, maxUsers={}",
                defaultTenant.getId(), currentUserCount, defaultTenant.getMaxUsers());
            throw new TenantUserQuotaExceededException(defaultTenant.getMaxUsers());
        }

        // Hash password (deferred until AFTER the quota gate so a flooded
        // tenant doesn't pay for a bcrypt round per rejected registration).
        String hashedPasswordString = passwordEncoder.encode(command.getPassword());
        HashedPassword hashedPassword = HashedPassword.of(hashedPasswordString);

        // Create user entity
        User user = User.builder()
            .email(email.getValue())
            .passwordHash(hashedPassword.getValue())
            .firstName(fullName.getFirstName())
            .lastName(fullName.getLastName())
            .tenant(defaultTenant)
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .build();

        // Save user
        User savedUser = userRepository.save(user);
        // Capture the id once (keeps entity.User method-call surface minimal).
        java.util.UUID newUserId = savedUser.getId();
        String newUserEmail = savedUser.getEmail();
        log.info("User registered successfully: {}", newUserId);
        auditLogPort.logUserRegistered(newUserId.toString(), newUserEmail, command.getIpAddress());
        eventPublisher.publishUserRegistered(newUserId.toString(), newUserEmail);

        // default-role-on-join (V64): a user who auto-joined a tenant via a
        // VERIFIED email domain is provisioned with that tenant's default member
        // role (falls back to the seeded baseline role). This is the in-platform
        // "JIT" — NOT external-IdP federation. Best-effort: a failure here never
        // rolls back the registration (the adapter swallows + logs).
        if (autoBoundViaVerifiedDomain[0]) {
            String assignedRole = memberRoleAssignmentPort.assignDefaultMemberRole(
                    newUserId, defaultTenant.getId());
            if (assignedRole != null) {
                log.info("Assigned default member role '{}' to auto-joined user {} (tenant {})",
                        assignedRole, newUserId, defaultTenant.getId());
            }
        }

        // Send email verification code
        try {
            String verificationCode = otpService.generate("email-verify:" + newUserId);
            emailService.sendOtp(newUserEmail, verificationCode,
                    com.fivucsas.identity.infrastructure.email.OtpPurpose.EMAIL_VERIFICATION, null);
            log.info("Email verification code sent to: {}", newUserEmail);
        } catch (Exception e) {
            log.warn("Failed to send email verification code to: {}", newUserEmail, e);
        }

        // Generate tokens
        String accessToken = tokenGenerator.generateAccessToken(savedUser.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            savedUser,
            command.getIpAddress(),
            command.getUserAgent()
        );

        // Map to response
        UserResponse userResponse = com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(savedUser);

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse);
    }

    /**
     * Resolve a tenant from the domain part of the user's email.
     *
     * <p>First consults the V44 {@code tenant_email_domains} table, which
     * supports the multi-domain case (a single tenant can claim several
     * domains, e.g. Marmara University owns both {@code marmara.edu.tr}
     * and {@code marun.edu.tr}). If no row matches, falls back to the
     * legacy {@code tenants.domain} column for tenants whose admin has
     * not yet migrated to the new table.</p>
     *
     * @param emailDomain the domain part of the registering user's email
     * @return the resolved tenant, or empty if no tenant claims the domain
     *         via either path
     */
    private java.util.Optional<Tenant> resolveTenantByEmailDomain(
            String emailDomain, boolean[] autoBoundViaVerifiedDomain) {
        if (emailDomain == null || emailDomain.isBlank()) {
            return java.util.Optional.empty();
        }
        // Only VERIFIED domains auto-bind a registrant to a tenant (V63). A
        // self-service onboarded tenant claims its domain unverified, so it must
        // not silently capture other people's signups until ownership is proven.
        java.util.Optional<TenantEmailDomain> mapped =
            tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue(emailDomain);
        if (mapped.isPresent()) {
            java.util.UUID tenantId = mapped.get().getTenantId();
            log.info("Resolved tenant {} for email domain '{}' via tenant_email_domains (verified)", tenantId, emailDomain);
            java.util.Optional<Tenant> resolved = tenantRepository.findById(tenantId);
            // Mark as a verified-domain auto-bind so the caller applies the
            // tenant's default member role on join (V64). The legacy
            // tenants.domain fallback below does NOT set this flag.
            resolved.ifPresent(t -> autoBoundViaVerifiedDomain[0] = true);
            return resolved;
        }
        java.util.Optional<Tenant> legacy =
            tenantRepository.findByLegacyDomainIgnoreCase(emailDomain);
        legacy.ifPresent(t -> log.info(
            "Resolved tenant {} for email domain '{}' via legacy tenants.domain (consider backfilling tenant_email_domains)",
            t.getId(), emailDomain));
        return legacy;
    }
}
