package com.fivucsas.identity.dto;

import com.fivucsas.identity.entity.UserStatus;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserRequest {

    @Size(min = 2, max = 100, message = "First name must be between 2 and 100 characters")
    private String firstName;

    @Size(min = 2, max = 100, message = "Last name must be between 2 and 100 characters")
    private String lastName;

    @Email(message = "Invalid email format")
    private String email;

    @Pattern(regexp = "^[0-9]{11}$", message = "ID number must be 11 digits")
    private String idNumber;

    /**
     * Phone number in strict E.164 format (USER-BUG-4 follow-up).
     * Required prefix `+`, country-code first digit 1-9, total 10-15 digits.
     * Twilio Verify matches `to` + `code` byte-for-byte: a non-E.164 input
     * sends to one normalized number but verifies against the raw string
     * the server stored, producing a silent send-OK / verify-FAIL.
     * <p>
     * Error code: {@code phone.e164} — consumed by formatApiError in the web client.
     */
    @Pattern(regexp = "^\\+[1-9]\\d{9,14}$",
             message = "phone.e164: Phone number must be in E.164 format (e.g. +905551234567)")
    private String phoneNumber;

    @Size(max = 500, message = "Address must not exceed 500 characters")
    private String address;

    private UserStatus status;

    /**
     * Platform-level tier ({@link com.fivucsas.identity.entity.UserType} NAME —
     * ROOT / TENANT_ADMIN / TENANT_MEMBER / GUEST). This is the SOLE authority
     * for global standing, independent of the within-tenant RBAC {@link #roleIds}.
     * See docs/IDENTITY_ROLE_UNIFICATION.md.
     *
     * <p><b>Authorization (fail-closed):</b> only a caller whose own
     * {@code user_type=ROOT} may SET or CHANGE this — especially granting ROOT or
     * TENANT_ADMIN. A non-ROOT caller that sends a value which would change the
     * target's tier is rejected with 403 (a TENANT_ADMIN can never self-elevate
     * to ROOT). {@code null} = leave the tier unchanged.</p>
     */
    private String userType;

    /**
     * Within-tenant RBAC role assignment — the COMPLETE desired set of role ids
     * for this user (replace semantics: roles not in the list are revoked,
     * roles in the list are assigned). {@code null} = leave assignments
     * untouched; an empty list = revoke all role assignments.
     *
     * <p><b>Authorization (fail-closed):</b> a TENANT_ADMIN may only assign roles
     * that belong to their own tenant (or global/system role definitions);
     * assigning a role scoped to another tenant is rejected with 403.</p>
     */
    private List<UUID> roleIds;
}
