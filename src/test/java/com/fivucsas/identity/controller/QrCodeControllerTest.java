package com.fivucsas.identity.controller;

import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("QrCodeController Tests")
class QrCodeControllerTest {

    @Mock private QrCodeService qrCodeService;

    @InjectMocks
    private QrCodeController qrCodeController;

    @Test
    @DisplayName("Should generate QR token for user")
    void shouldGenerateQrToken() {
        UUID userId = UUID.randomUUID();
        when(qrCodeService.generateToken(userId)).thenReturn("qr-token-abc123");

        ResponseEntity<Map<String, Object>> response = qrCodeController.generateQrToken(userId);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsEntry("token", "qr-token-abc123");
        assertThat(response.getBody()).containsEntry("expiresInSeconds", 300);
        assertThat(response.getBody()).containsEntry("userId", userId.toString());
    }

    @Test
    @DisplayName("Should invalidate QR token")
    void shouldInvalidateQrToken() {
        ResponseEntity<Void> response = qrCodeController.invalidateQrToken("qr-token-abc123");

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(qrCodeService).invalidateToken("qr-token-abc123");
    }
}
