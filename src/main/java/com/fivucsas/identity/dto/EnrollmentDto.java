package com.fivucsas.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnrollmentDto {

    private String id;
    private String userId;
    private String userName;
    private String userEmail;
    private String tenantId;
    private String status;
    private String faceImageUrl;
    private Instant enrolledAt;
    private Instant createdAt;
    private Instant updatedAt;
    private Double qualityScore;
    private Double livenessScore;
    private String errorCode;
    private String errorMessage;
    private Instant completedAt;
}
