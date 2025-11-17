package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

/**
 * Command for verifying biometric data.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains biometric verification data
 * - Command Pattern: Represents biometric verification action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyBiometricCommand {

    private String userId;
    private MultipartFile faceImage;
}
