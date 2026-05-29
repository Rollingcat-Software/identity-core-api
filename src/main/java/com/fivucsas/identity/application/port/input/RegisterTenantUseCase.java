package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RegisterTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantOnboardingResponse;

/**
 * Input port for public self-service tenant onboarding.
 *
 * <p>Drives the full sign-up of a brand-new organisation from a single
 * unauthenticated request: tenant, first TENANT_ADMIN user, per-tenant
 * TENANT_ADMIN role, primary email-domain claim, default APP_LOGIN auth flow,
 * and an email-verification mail. See
 * {@link com.fivucsas.identity.application.service.RegisterTenantService}.</p>
 */
public interface RegisterTenantUseCase {

    /**
     * Onboards a new organisation. The tenant is created in a not-yet-active
     * state (PENDING/TRIAL) and is activated once the admin verifies their
     * email.
     *
     * @param command the onboarding request
     * @return a summary of the created tenant + admin (no tokens issued)
     * @throws com.fivucsas.identity.domain.exception.DuplicateTenantException
     *         if the org name or derived slug is already taken (409)
     * @throws com.fivucsas.identity.domain.exception.DuplicateEmailException
     *         if the admin email is already registered (409)
     * @throws com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException
     *         if the email domain is already claimed by another tenant (409)
     * @throws com.fivucsas.identity.domain.exception.OnboardingValidationException
     *         if the request fails semantic validation (400)
     */
    TenantOnboardingResponse register(RegisterTenantCommand command);
}
