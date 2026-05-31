package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;

/**
 * Input port for user authentication use case.
 *
 * This interface defines the contract for authenticating users with credentials.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only authentication
 * - Dependency Inversion: Application defines the port
 * - Security: Handles credentials securely
 */
public interface AuthenticateUserUseCase {

    /**
     * Authenticates a user with email and password.
     *
     * @param command the authentication command containing credentials
     * @return AuthenticationResponse with access token, refresh token, and user data
     * @throws com.fivucsas.identity.domain.exception.InvalidCredentialsException if credentials are invalid
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    AuthenticationResponse execute(AuthenticateUserCommand command);

    /**
     * Identifier-first pre-flight tenant check. Given an email and a tenant-bound
     * OAuth clientId, throws {@link com.fivucsas.identity.domain.exception.TenantMismatchException}
     * (→ HTTP 403 TENANT_MISMATCH) if the email belongs to a DIFFERENT tenant than
     * the client — WITHOUT verifying any password or touching the lockout counter.
     * Lets the hosted login surface the "not a {tenant} member" error on the email
     * step instead of the later password step. Unknown email / non-tenant-bound
     * client / system-tenant client ⇒ silent no-op.
     *
     * @param email    the typed identifier
     * @param clientId the OAuth client_id of the hosted login surface (may be null)
     */
    void checkTenantEligibility(String email, String clientId);

    /**
     * Resolve the home-tenant id of the user that owns {@code email}, for the
     * cross-tenant dashboard's identifier-first step (so it can fetch that
     * tenant's login-config — Layer-1 methods + step count — at the email
     * screen). Returns {@code null} for an unknown email so the caller falls
     * back to the platform default (no enumeration beyond the password-step
     * gate). No password is checked and no lockout counter is touched.
     *
     * @param email the typed identifier
     * @return the user's tenant id, or {@code null} if no such user
     */
    java.util.UUID resolveHomeTenantId(String email);
}
