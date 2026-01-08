package com.fivucsas.identity.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Security helper service for @PreAuthorize expressions.
 *
 * Provides methods to check if the current authenticated user
 * is the owner of a resource, enabling self-access patterns.
 *
 * Usage in controllers:
 * <pre>
 * @PreAuthorize("hasAuthority('user:read') or @userSecurityService.isCurrentUser(#userId)")
 * </pre>
 */
@Service("userSecurityService")
@RequiredArgsConstructor
@Slf4j
public class UserSecurityService {

    /**
     * Checks if the given userId matches the currently authenticated user.
     *
     * @param userId the user ID to check (can be String or UUID)
     * @return true if the current user matches the given userId
     */
    public boolean isCurrentUser(String userId) {
        if (userId == null) {
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (principal == null) {
            return false;
        }

        String currentUserId = extractUserId(principal);
        if (currentUserId == null) {
            return false;
        }

        // Normalize both IDs for comparison
        String normalizedUserId = normalizeUuid(userId);
        String normalizedCurrentUserId = normalizeUuid(currentUserId);

        boolean matches = normalizedCurrentUserId.equals(normalizedUserId);
        log.debug("isCurrentUser check: userId={}, currentUserId={}, matches={}",
                normalizedUserId, normalizedCurrentUserId, matches);

        return matches;
    }

    /**
     * Checks if the given userId matches the currently authenticated user.
     * Overloaded method for UUID parameter.
     *
     * @param userId the user ID to check
     * @return true if the current user matches the given userId
     */
    public boolean isCurrentUser(UUID userId) {
        return userId != null && isCurrentUser(userId.toString());
    }

    /**
     * Gets the current authenticated user's ID.
     *
     * @return the current user's ID as a String, or null if not authenticated
     */
    public String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }

        Object principal = authentication.getPrincipal();
        return extractUserId(principal);
    }

    /**
     * Gets the current authenticated user's ID as UUID.
     *
     * @return the current user's ID as UUID, or null if not authenticated
     */
    public UUID getCurrentUserIdAsUUID() {
        String userId = getCurrentUserId();
        if (userId == null) {
            return null;
        }
        try {
            return UUID.fromString(userId);
        } catch (IllegalArgumentException e) {
            log.warn("Could not parse current user ID as UUID: {}", userId);
            return null;
        }
    }

    /**
     * Checks if the current user has a specific authority/permission.
     *
     * @param authority the authority to check (e.g., "user:read", "ROLE_ADMIN")
     * @return true if the current user has the authority
     */
    public boolean hasAuthority(String authority) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        return authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(authority));
    }

    /**
     * Checks if the current user has any of the specified authorities.
     *
     * @param authorities the authorities to check
     * @return true if the current user has at least one of the authorities
     */
    public boolean hasAnyAuthority(String... authorities) {
        for (String authority : authorities) {
            if (hasAuthority(authority)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the user ID from the authentication principal.
     * Supports UserDetails implementations and String principals.
     */
    private String extractUserId(Object principal) {
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            return ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        } else if (principal instanceof String) {
            return (String) principal;
        }
        return null;
    }

    /**
     * Normalizes a UUID string for comparison.
     * Handles both UUID format and plain strings.
     */
    private String normalizeUuid(String value) {
        if (value == null) {
            return null;
        }
        // Remove dashes and convert to lowercase for comparison
        return value.replace("-", "").toLowerCase();
    }
}
