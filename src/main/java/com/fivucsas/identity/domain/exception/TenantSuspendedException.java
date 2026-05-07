package com.fivucsas.identity.domain.exception;

import com.fivucsas.identity.entity.TenantStatus;

/**
 * P0-#8 (INVESTIGATION_MASTER_2026-05-07): thrown when a user attempts to
 * authenticate (or refresh an access token) against a tenant whose status is
 * not {@link TenantStatus#ACTIVE}.
 *
 * <p>{@link com.fivucsas.identity.entity.Tenant#canAcceptUsers()} existed in
 * the domain model with zero non-DTO callers — the auth path issued JWTs
 * regardless of {@code SUSPENDED}, {@code INACTIVE}, {@code PENDING}, or
 * {@code TRIAL} (when expired). This exception is fired by
 * {@link com.fivucsas.identity.application.service.AuthenticateUserService}
 * after fetching the user (i.e. after the email is known to exist) and by
 * {@link com.fivucsas.identity.application.service.RefreshAccessTokenService}
 * before minting a new access token, so suspended-tenant users cannot keep a
 * session alive via refresh.
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 423 Locked with body shape:
 * <pre>
 * {
 *   "errorCode": "TENANT_SUSPENDED",
 *   "message": "Tenant is currently SUSPENDED and cannot authenticate users",
 *   "status": "SUSPENDED",
 *   "path": "/api/v1/auth/login"
 * }
 * </pre>
 *
 * <p>423 Locked mirrors the existing
 * {@link com.fivucsas.identity.domain.exception.AccountLockedException}
 * surface — the resource is intact but temporarily inaccessible until an
 * operator reactivates the tenant.
 */
public class TenantSuspendedException extends DomainException {

    private static final String ERROR_CODE = "TENANT_SUSPENDED";

    private final TenantStatus status;

    public TenantSuspendedException(TenantStatus status) {
        super("Tenant is currently " + status + " and cannot authenticate users", ERROR_CODE);
        this.status = status;
    }

    public TenantStatus getStatus() {
        return status;
    }
}
