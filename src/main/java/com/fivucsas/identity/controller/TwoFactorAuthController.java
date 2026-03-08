package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.Disable2FACommand;
import com.fivucsas.identity.application.dto.command.Enable2FACommand;
import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.TwoFactorSetupResponse;
import com.fivucsas.identity.application.port.input.Disable2FAUseCase;
import com.fivucsas.identity.application.port.input.Enable2FAUseCase;
import com.fivucsas.identity.application.port.input.Setup2FAUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for two-factor authentication endpoints.
 *
 * Following hexagonal architecture principles.
 */
@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Two-Factor Authentication", description = "2FA management endpoints")
public class TwoFactorAuthController {

    private final Setup2FAUseCase setup2FAUseCase;
    private final Enable2FAUseCase enable2FAUseCase;
    private final Disable2FAUseCase disable2FAUseCase;

    @PostMapping("/setup")
    @Operation(
        summary = "Setup 2FA",
        description = "Initiates 2FA setup by generating secret and QR code",
        security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<TwoFactorSetupResponse> setup2FA(Authentication authentication) {
        log.info("2FA setup request from: {}", authentication.getName());

        GetUserByEmailQuery query = GetUserByEmailQuery.builder()
            .email(authentication.getName())
            .build();

        TwoFactorSetupResponse response = setup2FAUseCase.execute(query);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/enable")
    @Operation(
        summary = "Enable 2FA",
        description = "Enables 2FA after verifying the TOTP code",
        security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<Void> enable2FA(
            @RequestParam String verificationCode,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Enable 2FA request from: {}", authentication.getName());

        Enable2FACommand command = Enable2FACommand.builder()
            .email(authentication.getName())
            .verificationCode(verificationCode)
            .ipAddress(getClientIP(httpRequest))
            .build();

        enable2FAUseCase.execute(command);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/disable")
    @Operation(
        summary = "Disable 2FA",
        description = "Disables 2FA (requires password confirmation)",
        security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<Void> disable2FA(
            @RequestParam String password,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Disable 2FA request from: {}", authentication.getName());

        Disable2FACommand command = Disable2FACommand.builder()
            .email(authentication.getName())
            .password(password)
            .ipAddress(getClientIP(httpRequest))
            .build();

        disable2FAUseCase.execute(command);

        return ResponseEntity.ok().build();
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
