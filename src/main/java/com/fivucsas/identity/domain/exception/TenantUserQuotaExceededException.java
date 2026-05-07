package com.fivucsas.identity.domain.exception;

/**
 * P0-#7 (INVESTIGATION_MASTER_2026-05-07): thrown when a user-creation path
 * would exceed the tenant's configured {@code max_users} ceiling.
 *
 * <p>{@code tenants.max_users} (default 100) was surfaced in the admin UI but
 * had ZERO insert-path readers — every registration / admin-create path could
 * silently grow a tenant beyond its license. This exception is fired by
 * {@link com.fivucsas.identity.application.service.RegisterUserService} and
 * {@link com.fivucsas.identity.application.service.ManageUserService#createUser}
 * BEFORE the {@code users.save()} call, so the tenant cap is enforced
 * server-side regardless of caller surface.
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 409 Conflict with body shape:
 * <pre>
 * {
 *   "errorCode": "TENANT_USER_QUOTA_EXCEEDED",
 *   "message": "Tenant has reached its maximum user quota (100)",
 *   "maxUsers": 100,
 *   "path": "/api/v1/auth/register"
 * }
 * </pre>
 *
 * <p>Operators raise the cap via the admin-tenant edit screen (no code change
 * required); the field already lives on {@link com.fivucsas.identity.entity.Tenant}.
 */
public class TenantUserQuotaExceededException extends DomainException {

    private static final String ERROR_CODE = "TENANT_USER_QUOTA_EXCEEDED";

    private final int maxUsers;

    public TenantUserQuotaExceededException(int maxUsers) {
        super("Tenant has reached its maximum user quota (" + maxUsers + ")", ERROR_CODE);
        this.maxUsers = maxUsers;
    }

    public int getMaxUsers() {
        return maxUsers;
    }
}
