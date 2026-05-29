package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyEmailCommand;
import com.fivucsas.identity.application.port.input.VerifyEmailUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.TenantProvisioningPort;
import com.fivucsas.identity.domain.exception.InvalidTokenException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for email verification.
 *
 * Implements the VerifyEmailUseCase input port.
 * Logs all verification attempts to audit log.
 *
 * <p>Token-based path (distinct from {@code AuthController.verifyEmail}, which is
 * the JWT-gated OTP path for an already-logged-in user). This is the public path
 * used by self-service tenant onboarding: verifying the admin's email here also
 * activates the freshly-onboarded tenant (unless admin approval is required).</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyEmailService implements VerifyEmailUseCase {

    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;
    private final TenantProvisioningPort tenantProvisioningPort;

    @Value("${app.onboarding.require-admin-approval:false}")
    private boolean requireAdminApproval;

    @Override
    @Transactional
    public void execute(VerifyEmailCommand command) {
        log.info("Email verification attempt with token: {}", command.getToken());

        // Find user by verification token
        User user = userRepository.findByEmailVerificationToken(command.getToken())
            .orElseThrow(() -> {
                auditLogPort.logSecurityEvent(
                    "UNKNOWN",
                    "EMAIL_VERIFICATION_FAILED",
                    command.getIpAddress(),
                    "Invalid verification token"
                );
                return new InvalidTokenException("Invalid or expired verification token");
            });

        // Check if already verified
        if (user.isEmailVerified()) {
            log.info("Email already verified for user: {}", user.getEmail());
            return;
        }

        // Check if token is expired
        if (user.isVerificationTokenExpired()) {
            log.warn("Verification token expired for user: {}", user.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "EMAIL_VERIFICATION_FAILED",
                command.getIpAddress(),
                "Token expired"
            );
            throw new InvalidTokenException("Verification token has expired. Please request a new one.");
        }

        // Verify email
        boolean success = user.verifyEmail(command.getToken());
        if (!success) {
            log.error("Email verification failed for user: {}", user.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "EMAIL_VERIFICATION_FAILED",
                command.getIpAddress(),
                "Token mismatch"
            );
            throw new InvalidTokenException("Failed to verify email");
        }

        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "EMAIL_VERIFIED",
            command.getIpAddress(),
            "Email verification successful"
        );

        // Self-service onboarding hook: when the verified user is a TENANT_ADMIN
        // (the first admin of a self-onboarded tenant), verification proves
        // control of an address at the claimed domain → activate the tenant out
        // of its PENDING/TRIAL state. When admin approval is required the tenant
        // is left PENDING for a SUPER_ADMIN even after verification.
        if (user.isTenantAdmin()) {
            boolean activated = tenantProvisioningPort
                    .activateTenantForVerifiedAdmin(user.getId(), requireAdminApproval);
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                activated ? "TENANT_ACTIVATED_ON_VERIFICATION" : "TENANT_PENDING_ADMIN_APPROVAL",
                command.getIpAddress(),
                activated
                    ? "Tenant activated after admin email verification"
                    : "Tenant left pending — admin approval required after email verification"
            );
        }
    }
}
