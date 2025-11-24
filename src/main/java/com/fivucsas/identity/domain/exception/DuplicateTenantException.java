package com.fivucsas.identity.domain.exception;

/**
 * Exception thrown when attempting to create a tenant with duplicate name or slug.
 */
public class DuplicateTenantException extends DomainException {

    public DuplicateTenantException(String field, String value) {
        super("Tenant with " + field + " already exists: " + value);
    }
}
