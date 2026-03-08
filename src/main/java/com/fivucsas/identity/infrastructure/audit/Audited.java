package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.domain.model.AuditAction;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark methods that should be audited.
 * When applied to a method, the AuditLoggingAspect will automatically
 * create an audit log entry when the method executes.
 *
 * Example:
 * <pre>
 * @Audited(action = AuditAction.USER_CREATED, resourceType = "User")
 * public UserResponse createUser(CreateUserCommand command) {
 *     // implementation
 * }
 * </pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    /**
     * The action being performed.
     */
    AuditAction action();

    /**
     * The type of resource being acted upon (e.g., "User", "Tenant", "Role").
     */
    String resourceType() default "";

    /**
     * The name of the parameter that contains the resource ID.
     * Default is "id".
     */
    String resourceIdParam() default "id";

    /**
     * Additional parameters to include in the audit details.
     */
    String[] includeParams() default {};
}
