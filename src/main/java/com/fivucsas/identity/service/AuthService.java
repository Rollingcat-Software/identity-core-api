package com.fivucsas.identity.service;

import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.dto.UserDto;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request, String ipAddress, String userAgent) {
        log.info("Registering new user: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException(request.getEmail());
        }

        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .build();

        User savedUser = userRepository.save(user);

        if (savedUser == null) {
            log.error("Failed to save user - repository returned null");
            throw new RuntimeException("Failed to create user");
        }

        log.info("User registered successfully: {}", savedUser.getId());

        String accessToken = jwtService.generateAccessToken(savedUser.getEmail());
        String refreshToken = refreshTokenService.createRefreshToken(savedUser, ipAddress, userAgent).getToken();
        UserDto userDto = mapToDto(savedUser);

        return AuthResponse.of(accessToken, refreshToken, userDto);
    }

    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        log.info("Login attempt for user: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException());

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            log.warn("Invalid password for user: {}", request.getEmail());
            throw new InvalidCredentialsException();
        }

        log.info("User logged in successfully: {}", user.getId());

        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = refreshTokenService.createRefreshToken(user, ipAddress, userAgent).getToken();
        UserDto userDto = mapToDto(user);

        return AuthResponse.of(accessToken, refreshToken, userDto);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenStr, String ipAddress, String userAgent) {
        log.info("Refreshing token");

        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenStr);
        refreshTokenService.verifyExpiration(refreshToken);

        User user = refreshToken.getUser();

        // Rotate refresh token for security
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken, ipAddress, userAgent);

        String accessToken = jwtService.generateAccessToken(user.getEmail());
        UserDto userDto = mapToDto(user);

        log.info("Token refreshed successfully for user: {}", user.getEmail());

        return AuthResponse.of(accessToken, newRefreshToken.getToken(), userDto);
    }

    @Transactional
    public void logout(String refreshTokenStr) {
        log.info("Logout request");

        try {
            refreshTokenService.revokeToken(refreshTokenStr);
            log.info("Logout successful");
        } catch (Exception e) {
            log.warn("Logout attempted with invalid token: {}", e.getMessage());
            // Don't throw exception - logout should be idempotent
        }
    }

    @Transactional
    public void logoutAll(String email) {
        log.info("Logout all sessions for user: {}", email);

        User user = getUserByEmail(email);
        refreshTokenService.revokeAllUserTokens(user);

        log.info("All sessions logged out for user: {}", email);
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException(email));
    }

    public UserDto mapToDto(User user) {
        if (user == null) {
            log.error("mapToDto called with null user");
            throw new RuntimeException("Cannot map null user to DTO");
        }

        return UserDto.builder()
                .id(user.getId() != null ? user.getId().toString() : null)
                .name(user.getFullName())
                .email(user.getEmail())
                .idNumber(user.getIdNumber())
                .phoneNumber(user.getPhoneNumber())
                .address(user.getAddress())
                .status(user.getStatus())
                .isBiometricEnrolled(user.isBiometricEnrolled())
                .enrolledAt(user.getEnrolledAt())
                .lastVerifiedAt(user.getLastVerifiedAt())
                .verificationCount(user.getVerificationCount())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
