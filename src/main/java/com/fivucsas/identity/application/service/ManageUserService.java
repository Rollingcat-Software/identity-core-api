package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.user.*;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for user management (CRUD operations).
 *
 * Implements the ManageUserUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageUserService implements ManageUserUseCase {

    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;

    @Override
    @Transactional
    public UserResponse createUser(CreateUserCommand command) {
        log.info("Creating new user: {}", command.getEmail());

        if (userRepository.existsByEmail(command.getEmail())) {
            throw new DuplicateEmailException(command.getEmail());
        }

        // Validate using value objects
        Email email = Email.of(command.getEmail());
        FullName fullName = FullName.of(command.getFirstName(), command.getLastName());
        HashedPassword hashedPassword = HashedPassword.of(passwordEncoder.encode(command.getPassword()));

        User user = User.builder()
            .email(email.getValue())
            .passwordHash(hashedPassword.getValue())
            .firstName(fullName.getFirstName())
            .lastName(fullName.getLastName())
            .idNumber(command.getIdNumber())
            .phoneNumber(command.getPhoneNumber())
            .address(command.getAddress())
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .build();

        user = userRepository.save(user);
        log.info("User created successfully: {}", user.getId());

        return mapToUserResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(GetUserByIdQuery query) {
        log.info("Fetching user by id: {}", query.getUserId());

        UUID uuid = UUID.fromString(query.getUserId());
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(query.getUserId()));

        return mapToUserResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers(GetAllUsersQuery query) {
        log.info("Fetching all users");

        return userRepository.findAll().stream()
            .map(this::mapToUserResponse)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> searchUsers(SearchUsersQuery query) {
        log.info("Searching users with query: {}", query.getSearchQuery());

        return userRepository.searchUsers(query.getSearchQuery()).stream()
            .map(this::mapToUserResponse)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public UserResponse updateUser(UpdateUserCommand command) {
        log.info("Updating user: {}", command.getUserId());

        UUID uuid = UUID.fromString(command.getUserId());
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // Use value objects for validation
        if (command.getFirstName() != null && command.getLastName() != null) {
            FullName fullName = FullName.of(command.getFirstName(), command.getLastName());
            user.setFirstName(fullName.getFirstName());
            user.setLastName(fullName.getLastName());
        } else {
            if (command.getFirstName() != null) {
                user.setFirstName(command.getFirstName());
            }
            if (command.getLastName() != null) {
                user.setLastName(command.getLastName());
            }
        }

        if (command.getPhoneNumber() != null) {
            PhoneNumber phone = PhoneNumber.ofNullable(command.getPhoneNumber());
            user.updatePhoneNumber(phone);
        }

        if (command.getAddress() != null) {
            Address address = Address.ofNullable(command.getAddress());
            user.updateAddress(address);
        }

        user = userRepository.save(user);
        log.info("User updated successfully: {}", user.getId());

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        log.info("Deleting user: {}", userId);

        UUID uuid = UUID.fromString(userId);
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(userId));

        userRepository.delete(user);
        log.info("User deleted successfully: {}", userId);
    }

    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
            .id(user.getId().toString())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .phoneNumber(user.getPhoneNumber())
            .address(user.getAddress())
            .idNumber(user.getIdNumber() != null ? user.getIdNumberAsValueObject().getMasked() : null)
            .status(user.getStatus().name())
            .isBiometricEnrolled(user.isBiometricEnrolled())
            .enrolledAt(user.getEnrolledAt())
            .lastVerifiedAt(user.getLastVerifiedAt())
            .verificationCount(user.getVerificationCount())
            .createdAt(user.getCreatedAt())
            .updatedAt(user.getUpdatedAt())
            .build();
    }
}
