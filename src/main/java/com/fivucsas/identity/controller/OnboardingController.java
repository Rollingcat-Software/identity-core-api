package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterTenantCommand;
import com.fivucsas.identity.application.dto.command.VerifyEmailCommand;
import com.fivucsas.identity.application.dto.response.TenantOnboardingResponse;
import com.fivucsas.identity.application.port.input.RegisterTenantUseCase;
import com.fivucsas.identity.application.port.input.VerifyEmailUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * PUBLIC self-service tenant onboarding.
 *
 * <p>Unauthenticated entry point that lets a brand-new organisation sign itself
 * up — distinct from {@code POST /api/v1/tenants} (ROOT-only, bare tenant). Both
 * endpoints here are added to the SecurityConfig permit-all list and are
 * rate-limited per IP by {@code RateLimitFilter}.</p>
 *
 * <ul>
 *   <li>{@code POST /api/v1/onboarding/register} — atomically creates the
 *       tenant + first TENANT_ADMIN + role + default auth flow + claims the
 *       (unverified) email domain, and emails a verification link.</li>
 *   <li>{@code POST /api/v1/onboarding/verify-email} — completes verification by
 *       token and activates the tenant (token-based, no JWT). A convenience
 *       {@code GET} variant accepts the token as a query param so the link in
 *       the email can be followed directly.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/onboarding")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Onboarding", description = "Public self-service tenant sign-up")
public class OnboardingController {

    private final RegisterTenantUseCase registerTenantUseCase;
    private final VerifyEmailUseCase verifyEmailUseCase;

    @PostMapping("/register")
    @Operation(summary = "Register a new organisation (public self-service)")
    public ResponseEntity<TenantOnboardingResponse> register(
            @Valid @RequestBody RegisterTenantRequest request,
            HttpServletRequest httpRequest) {

        log.info("AUDIT: Onboarding request — org='{}', adminEmail={}, ip={}",
                request.getOrgName(), request.getAdminEmail(), clientIp(httpRequest));

        RegisterTenantCommand command = RegisterTenantCommand.builder()
                .orgName(request.getOrgName())
                .slug(request.getSlug())
                .adminEmail(request.getAdminEmail())
                .adminPassword(request.getAdminPassword())
                .adminFirstName(request.getAdminFirstName())
                .adminLastName(request.getAdminLastName())
                .emailDomain(request.getEmailDomain())
                .ipAddress(clientIp(httpRequest))
                .userAgent(httpRequest.getHeader("User-Agent"))
                .build();

        TenantOnboardingResponse response = registerTenantUseCase.register(command);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verify the admin email and activate the new tenant (token-based)")
    public ResponseEntity<Map<String, Object>> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request,
            HttpServletRequest httpRequest) {
        verifyEmailUseCase.execute(VerifyEmailCommand.builder()
                .token(request.getToken())
                .ipAddress(clientIp(httpRequest))
                .build());
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Email verified. Your organisation is being activated."));
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verify the admin email via the link in the verification email")
    public ResponseEntity<Map<String, Object>> verifyEmailViaLink(
            @RequestParam("token") String token,
            HttpServletRequest httpRequest) {
        verifyEmailUseCase.execute(VerifyEmailCommand.builder()
                .token(token)
                .ipAddress(clientIp(httpRequest))
                .build());
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Email verified. Your organisation is being activated."));
    }

    private String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    // ========== Request DTOs ==========

    @Data
    public static class RegisterTenantRequest {

        @NotBlank(message = "Organisation name is required")
        @Size(min = 2, max = 100, message = "Organisation name must be between 2 and 100 characters")
        private String orgName;

        /** Optional — derived from orgName when blank. URL-safe slug. */
        @Size(max = 50, message = "Slug must not exceed 50 characters")
        @Pattern(regexp = "^$|^[a-zA-Z0-9-]+$",
                message = "Slug may only contain letters, digits and hyphens")
        private String slug;

        @NotBlank(message = "Admin email is required")
        @Email(message = "Admin email must be valid")
        @Size(max = 255)
        private String adminEmail;

        @NotBlank(message = "Admin password is required")
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        private String adminPassword;

        @NotBlank(message = "Admin first name is required")
        @Size(max = 100)
        private String adminFirstName;

        @NotBlank(message = "Admin last name is required")
        @Size(max = 100)
        private String adminLastName;

        /** Optional — derived from the admin email's domain when blank. */
        @Size(max = 253, message = "Email domain must not exceed 253 characters")
        private String emailDomain;
    }

    @Data
    public static class VerifyEmailRequest {
        @NotBlank(message = "token is required")
        private String token;
    }
}
