package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

/**
 * Command for enrolling biometric data.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains biometric enrollment data
 * - Command Pattern: Represents biometric enrollment action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnrollBiometricCommand {

    private String userId;
    private MultipartFile faceImage;
}
