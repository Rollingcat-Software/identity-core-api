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
    private String status;
    private Instant enrolledAt;
}
