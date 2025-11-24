package com.fivucsas.identity.domain.exception;

/**
 * Exception thrown when a tenant is not found.
 */
public class TenantNotFoundException extends DomainException {

    public TenantNotFoundException(String identifier) {
        super("Tenant not found: " + identifier);
    }
}
