package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantOnboardingResponse;
import com.fivucsas.identity.application.port.input.RegisterTenantUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TenantProvisioningPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.DuplicateTenantException;
import com.fivucsas.identity.domain.exception.OnboardingValidationException;
import com.fivucsas.identity.domain.exception.PersonalEmailNotAllowedException;
import com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException;
import com.fivucsas.identity.domain.model.user.Email;
import com.fivucsas.identity.domain.model.user.FullName;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Use case service for PUBLIC self-service tenant onboarding.
 *
 * <p>Today tenants are ROOT-provisioned via {@code POST /api/v1/tenants}
 * ({@code @rbac.isRoot()}), which only creates a bare {@link
 * com.fivucsas.identity.domain.model.tenant.Tenant}. This service lets a brand
 * new organisation sign itself up from a single unauthenticated request and, in
 * one transaction, provisions the tenant, its first TENANT_ADMIN user, a
 * per-tenant TENANT_ADMIN role, the primary email-domain claim, and a default
 * APP_LOGIN auth flow — then emails the admin a verification link.</p>
 *
 * <h2>Design decision — lifecycle</h2>
 * <p>New self-service tenants are created in a <b>not-yet-active</b> state. The
 * admin must verify their email (which proves control of an address at the
 * claimed domain) before the tenant becomes {@code ACTIVE}. The starting state
 * is {@code TRIAL} by default; when {@code app.onboarding.require-admin-approval}
 * is {@code true} the tenant starts and STAYS {@code PENDING} until a SUPER_ADMIN
 * approves it — verification alone is not enough. See
 * {@link com.fivucsas.identity.application.service.VerifyEmailService} for the
 * activation hook.</p>
 *
 * <h2>Boundary note</h2>
 * <p>The entity-level wiring (creating {@code entity.User}, the role, the
 * email-domain row and the auth flow) lives in the infrastructure adapter behind
 * {@link TenantProvisioningPort}. This service only orchestrates, validates and
 * sends the email, so it never imports {@code entity.User} and respects
 * {@code UserDomainBoundaryTest}.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterTenantService implements RegisterTenantUseCase {

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final TenantEmailDomainRepository tenantEmailDomainRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TenantProvisioningPort tenantProvisioningPort;
    private final EmailService emailService;
    private final AuditLogPort auditLogPort;

    @Value("${app.onboarding.require-admin-approval:false}")
    private boolean requireAdminApproval;

    @Value("${app.onboarding.enabled:true}")
    private boolean onboardingEnabled;

    /**
     * Public / free / disposable email providers that may NOT be used to onboard
     * a tenant. Configurable via {@code app.onboarding.blocked-email-domains}
     * (comma-separated). A real organisation signs up with its own corporate
     * domain. Entries are matched case-insensitively; an entry ending in a dot
     * (e.g. {@code "gmx."}) matches that label and any TLD/sub-suffix
     * ({@code gmx.com}, {@code gmx.net}, {@code gmx.de}, …).
     */
    @Value("${APP_ONBOARDING_BLOCKED_EMAIL_DOMAINS:${app.onboarding.blocked-email-domains:"
            + "gmail.com,googlemail.com,outlook.com,hotmail.com,live.com,msn.com,"
            + "yahoo.com,yahoo.co.uk,ymail.com,icloud.com,me.com,mac.com,"
            + "proton.me,protonmail.com,pm.me,aol.com,mail.com,gmx.,yandex.,"
            + "zoho.com,fastmail.com,tutanota.com,tuta.io,hushmail.com,"
            + "mailinator.com,guerrillamail.com,10minutemail.com,tempmail.com,"
            + "temp-mail.org,throwawaymail.com,getnada.com,sharklasers.com,"
            + "trashmail.com,yopmail.com,dispostable.com,maildrop.cc,mintemail.com"
            + "}}")
    private String blockedEmailDomainsCsv;

    /** Max attempts to find a free slug by appending a numeric suffix. */
    private static final int MAX_SLUG_SUFFIX = 1000;

    @Override
    @Transactional
    public TenantOnboardingResponse register(RegisterTenantCommand command) {
        if (!onboardingEnabled) {
            throw new OnboardingValidationException(
                    "Self-service onboarding is currently disabled.");
        }

        log.info("AUDIT: Self-service tenant onboarding attempt — org='{}', adminEmail={}, ip={}",
                command.getOrgName(), command.getAdminEmail(), command.getIpAddress());

        // ---- Validate + normalise inputs ----------------------------------
        final String orgName = requireText(command.getOrgName(), "Organisation name");
        // Validate value objects up front (cheap; surfaces clean 400s before any insert).
        final Email adminEmail = Email.of(command.getAdminEmail());
        final FullName adminName = FullName.of(command.getAdminFirstName(), command.getAdminLastName());
        final String rawPassword = requireText(command.getAdminPassword(), "Admin password");

        // ---- Uniqueness pre-checks (clean 409s, no partial inserts) --------
        if (tenantRepository.existsByName(orgName)) {
            throw new DuplicateTenantException("name", orgName);
        }
        if (userRepository.existsByEmail(adminEmail.getValue())) {
            // Prevents an onboarding request from being used to (re)claim an
            // email that already belongs to a user in ANY existing tenant —
            // i.e. no escalation into an existing tenant via onboarding.
            throw new DuplicateEmailException(adminEmail.getValue());
        }

        // Reject personal/free/disposable email providers BEFORE any work — an
        // organisation must onboard with its own corporate domain (422). Checked
        // against the ADMIN EMAIL's own domain, regardless of any override
        // supplied in emailDomain, so the block can't be side-stepped.
        if (isBlockedEmailDomain(adminEmail.getDomain())) {
            throw new PersonalEmailNotAllowedException(adminEmail.getDomain());
        }

        final String slug = resolveUniqueSlug(command.getSlug(), orgName);

        final String emailDomain = resolveEmailDomain(command.getEmailDomain(), adminEmail);
        // A supplied override must also not be a personal/free provider.
        if (isBlockedEmailDomain(emailDomain)) {
            throw new PersonalEmailNotAllowedException(emailDomain);
        }
        tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase(emailDomain)
                .ifPresent(existing -> {
                    throw TenantEmailDomainConflictException.alreadyClaimed(emailDomain);
                });

        // ---- Hash password (after all gates so rejects don't pay bcrypt) ---
        final String hashedPassword = passwordEncoder.encode(rawPassword);

        final String initialStatus = requireAdminApproval ? "PENDING" : "TRIAL";

        // ---- Provision everything in one transaction -----------------------
        TenantProvisioningPort.Result result = tenantProvisioningPort.provision(
                new TenantProvisioningPort.Params(
                        orgName,
                        slug,
                        adminEmail.getValue(),
                        hashedPassword,
                        adminName.getFirstName(),
                        adminName.getLastName(),
                        emailDomain,
                        initialStatus));

        // userId=null: self-onboarding is pre-auth (no established user actor),
        // and audit_logs.user_id is an FK to users — passing the new tenant id
        // here violated audit_logs_user_id_fkey and rolled back the whole
        // onboarding (this insert is in the same tx; the FK fails at commit).
        // The tenant, slug, domain and admin are all captured in `details`.
        auditLogPort.logSecurityEvent(
                null,
                "TENANT_SELF_ONBOARDED",
                command.getIpAddress(),
                String.format("Self-service tenant '%s' (slug=%s, domain=%s, id=%s) onboarded; "
                                + "admin=%s, status=%s, awaiting email verification",
                        orgName, slug, emailDomain, result.tenantId(), adminEmail.getValue(), initialStatus));

        // ---- Send the verification email (best-effort; never fails the tx) -
        try {
            emailService.sendTenantOnboardingVerification(
                    adminEmail.getValue(),
                    adminName.getFirstName(),
                    orgName,
                    result.emailVerificationToken());
        } catch (Exception e) {
            // Mirror RegisterUserService: a mail failure must not roll back a
            // committed onboarding. The admin can request a resend.
            log.warn("Failed to send onboarding verification email to {}", adminEmail.getValue(), e);
        }

        return TenantOnboardingResponse.builder()
                .tenantId(result.tenantId().toString())
                .slug(slug)
                .orgName(orgName)
                .adminUserId(result.adminUserId().toString())
                .adminEmail(adminEmail.getValue())
                .emailDomain(emailDomain)
                .status(initialStatus)
                .requiresAdminApproval(requireAdminApproval)
                .message(requireAdminApproval
                        ? "Organisation registered. Verify your email, then an administrator "
                          + "will review and activate your account."
                        : "Organisation registered. Check your inbox to verify your email and "
                          + "activate your account.")
                .build();
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    /**
     * True when {@code domain} is on the configured personal/free/disposable
     * blocklist. Exact match, or prefix match for entries ending in a dot
     * (e.g. {@code "gmx."} blocks {@code gmx.com}, {@code gmx.net}, …).
     */
    private boolean isBlockedEmailDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return false;
        }
        String d = domain.trim().toLowerCase(Locale.ROOT);
        Set<String> blocked = parseBlockedDomains();
        if (blocked.contains(d)) {
            return true;
        }
        // Wildcard-suffix entries: "gmx." matches "gmx.com", "gmx.de", …
        return blocked.stream()
                .filter(b -> b.endsWith("."))
                .anyMatch(d::startsWith);
    }

    private Set<String> parseBlockedDomains() {
        if (blockedEmailDomainsCsv == null || blockedEmailDomainsCsv.isBlank()) {
            return Set.of();
        }
        return java.util.Arrays.stream(blockedEmailDomainsCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new OnboardingValidationException(field + " is required.");
        }
        return value.trim();
    }

    /**
     * Resolves the email domain to claim. Uses the caller-supplied value when
     * present (lower-cased, '@' stripped), else derives it from the admin email.
     */
    private String resolveEmailDomain(String supplied, Email adminEmail) {
        String domain;
        if (supplied != null && !supplied.isBlank()) {
            domain = supplied.trim().toLowerCase(Locale.ROOT);
            // Tolerate a pasted full address or a leading '@'.
            int at = domain.lastIndexOf('@');
            if (at >= 0) {
                domain = domain.substring(at + 1);
            }
        } else {
            domain = adminEmail.getDomain();
        }
        if (domain == null || domain.isBlank() || !domain.contains(".")) {
            throw new OnboardingValidationException(
                    "Could not determine a valid email domain. Provide a valid 'emailDomain' "
                            + "or use a corporate admin email address.");
        }
        return domain;
    }

    /**
     * Derives a unique, URL-safe slug. If the caller supplied one we normalise
     * it; otherwise we slugify the org name. On collision we append {@code -2},
     * {@code -3}, … until a free slug is found.
     */
    private String resolveUniqueSlug(String suppliedSlug, String orgName) {
        String base = (suppliedSlug != null && !suppliedSlug.isBlank())
                ? slugify(suppliedSlug)
                : slugify(orgName);
        if (base.isBlank()) {
            throw new OnboardingValidationException(
                    "Could not derive a slug from the organisation name; please supply a 'slug'.");
        }
        // Clamp to the column limit (tenants.slug VARCHAR(50)), leaving room for a suffix.
        if (base.length() > 45) {
            base = base.substring(0, 45);
        }

        if (!tenantRepository.existsBySlug(base)) {
            return base;
        }
        // If the caller explicitly chose this slug, a collision is a hard 409
        // rather than a silent rename (they get to see/correct it).
        if (suppliedSlug != null && !suppliedSlug.isBlank()) {
            throw new DuplicateTenantException("slug", base);
        }
        for (int i = 2; i <= MAX_SLUG_SUFFIX; i++) {
            String candidate = base + "-" + i;
            if (!tenantRepository.existsBySlug(candidate)) {
                return candidate;
            }
        }
        throw new OnboardingValidationException(
                "Could not allocate a unique slug for '" + orgName + "'; please supply a 'slug'.");
    }

    /**
     * Lower-cases, replaces any run of non-alphanumerics with a single hyphen,
     * and trims leading/trailing hyphens. ASCII-only output (matches the
     * existing slug convention in the codebase).
     */
    private static String slugify(String input) {
        String s = input.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-+)|(-+$)", "");
        return s;
    }
}
