package com.fivucsas.identity.dto;

import com.fivucsas.identity.entity.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private String id;
    private String name;
    private String email;
    private String idNumber;
    private String phoneNumber;
    private String address;
    private UserStatus status;
    private boolean isBiometricEnrolled;
    private Instant enrolledAt;
    private Instant lastVerifiedAt;
    private Integer verificationCount;
    private Instant createdAt;
    private Instant updatedAt;
}
