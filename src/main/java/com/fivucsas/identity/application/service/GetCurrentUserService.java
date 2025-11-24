package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.GetCurrentUserUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for getting current authenticated user.
 *
 * Implements the GetCurrentUserUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GetCurrentUserService implements GetCurrentUserUseCase {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserResponse execute(GetUserByEmailQuery query) {
        log.info("Getting current user: {}", query.getEmail());

        User user = userRepository.findByEmail(query.getEmail())
            .orElseThrow(() -> new UserNotFoundException(query.getEmail()));

        return mapToUserResponse(user);
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
