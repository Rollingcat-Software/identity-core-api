package com.fivucsas.identity.controller;

import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RefreshTokenRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.dto.UserDto;
import com.fivucsas.identity.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication endpoints")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        log.info("Register request received for email: {}", request.getEmail());
        String ipAddress = getClientIP(httpRequest);
        String userAgent = getUserAgent(httpRequest);
        AuthResponse response = authService.register(request, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    @Operation(summary = "Login with email and password")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        log.info("Login request received for email: {}", request.getEmail());
        String ipAddress = getClientIP(httpRequest);
        String userAgent = getUserAgent(httpRequest);
        AuthResponse response = authService.login(request, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        log.info("Refresh token request received");
        String ipAddress = getClientIP(httpRequest);
        String userAgent = getUserAgent(httpRequest);
        AuthResponse response = authService.refreshToken(request.getRefreshToken(), ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout and revoke refresh token")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout request received");
        authService.logout(request.getRefreshToken());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    @Operation(summary = "Get current authenticated user", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<UserDto> getCurrentUser(Authentication authentication) {
        log.info("Get current user request");
        String email = authentication.getName();
        UserDto user = authService.mapToDto(authService.getUserByEmail(email));
        return ResponseEntity.ok(user);
    }

    @GetMapping("/health")
    @Operation(summary = "Health check")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Auth service is healthy");
    }

    // Utility methods
    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

    private String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }
}
