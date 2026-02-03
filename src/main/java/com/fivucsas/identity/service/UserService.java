package com.fivucsas.identity.service;

import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.dto.CreateUserRequest;
import com.fivucsas.identity.dto.UpdateUserRequest;
import com.fivucsas.identity.dto.UserDto;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final com.fivucsas.identity.repository.UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers() {
        log.info("Fetching all users");
        return userRepository.findAll().stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDto getUserById(String id) {
        log.info("Fetching user by id: {}", id);
        UUID uuid = UUID.fromString(id);
        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new UserNotFoundException(id));
        return mapToDto(user);
    }

    @Transactional
    public UserDto createUser(CreateUserRequest request) {
        log.info("Creating new user: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException(request.getEmail());
        }

        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .idNumber(request.getIdNumber())
                .phoneNumber(request.getPhoneNumber())
                .address(request.getAddress())
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .build();

        user = userRepository.save(user);
        log.info("User created successfully: {}", user.getId());

        return mapToDto(user);
    }

    @Transactional
    public UserDto updateUser(String id, UpdateUserRequest request) {
        log.info("Updating user: {}", id);
        UUID uuid = UUID.fromString(id);
        
        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new UserNotFoundException(id));

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new IllegalArgumentException("Email already exists: " + request.getEmail());
            }
            user.setEmail(request.getEmail());
        }
        if (request.getIdNumber() != null) {
            user.setIdNumber(request.getIdNumber());
        }
        if (request.getPhoneNumber() != null) {
            user.setPhoneNumber(request.getPhoneNumber());
        }
        if (request.getAddress() != null) {
            user.setAddress(request.getAddress());
        }
        if (request.getStatus() != null) {
            user.setStatus(request.getStatus());
        }

        user = userRepository.save(user);
        log.info("User updated successfully: {}", user.getId());

        return mapToDto(user);
    }

    @Transactional
    public void deleteUser(String id) {
        log.info("Deleting user: {}", id);
        UUID uuid = UUID.fromString(id);
        
        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new UserNotFoundException(id));

        userRepository.delete(user);
        log.info("User deleted successfully: {}", id);
    }

    @Transactional(readOnly = true)
    public List<UserDto> searchUsers(String query) {
        log.info("Searching users with query: {}", query);
        
        if (query == null || query.trim().isEmpty()) {
            return getAllUsers();
        }

        return userRepository.searchUsers(query).stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    private UserDto mapToDto(User user) {
        return UserDto.builder()
                .id(user.getId().toString())
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
