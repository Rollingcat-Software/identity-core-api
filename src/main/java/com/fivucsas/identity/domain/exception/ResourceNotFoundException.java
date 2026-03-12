package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a requested resource cannot be found.
 */
public class ResourceNotFoundException extends DomainException {

    private static final String ERROR_CODE = "RESOURCE_NOT_FOUND";

    public ResourceNotFoundException(String resourceType, String identifier) {
        super(String.format("%s not found: %s", resourceType, identifier), ERROR_CODE);
    }
}
