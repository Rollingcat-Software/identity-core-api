package com.fivucsas.identity.service;

import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.dto.UserDto;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.UserRepository;
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

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering new user: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists: " + request.getEmail());
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

        String token = jwtService.generateToken(savedUser.getEmail());
        UserDto userDto = mapToDto(savedUser);

        return AuthResponse.of(token, userDto);
    }

    public AuthResponse login(LoginRequest request) {
        log.info("Login attempt for user: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            log.warn("Invalid password for user: {}", request.getEmail());
            throw new RuntimeException("Invalid credentials");
        }

        log.info("User logged in successfully: {}", user.getId());

        String token = jwtService.generateToken(user.getEmail());
        UserDto userDto = mapToDto(user);

        return AuthResponse.of(token, userDto);
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found: " + email));
    }

    private UserDto mapToDto(User user) {
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
