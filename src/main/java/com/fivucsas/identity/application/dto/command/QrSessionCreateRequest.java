package com.fivucsas.identity.application.dto.command;

/**
 * Client request DTO for creating a QR login session.
 */
public record QrSessionCreateRequest(String platform) {}
