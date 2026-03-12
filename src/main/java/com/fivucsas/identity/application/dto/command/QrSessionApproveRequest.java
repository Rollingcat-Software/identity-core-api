package com.fivucsas.identity.application.dto.command;

/**
 * Client request DTO for approving a QR login session.
 */
public record QrSessionApproveRequest(String approverPlatform) {}
