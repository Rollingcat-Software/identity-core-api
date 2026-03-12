package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.QrSessionApproveRequest;
import com.fivucsas.identity.application.dto.command.QrSessionCreateRequest;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.infrastructure.qrcode.QrSessionService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("QrSessionController Tests")
class QrSessionControllerTest {

    @Mock private QrSessionService qrSessionService;
    @Mock private RbacAuthorizationService rbacService;

    @InjectMocks
    private QrSessionController controller;

    private UUID userId;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        Tenant tenant = Tenant.builder()
                .id(UUID.randomUUID())
                .name("Test Tenant")
                .slug("test-tenant")
                .contactEmail("admin@test.com")
                .status(TenantStatus.ACTIVE)
                .build();
        testUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .tenant(tenant)
                .build();
    }

    @Nested
    @DisplayName("Create Session")
    class CreateSession {

        @Test
        @DisplayName("Should create session with platform")
        void shouldCreateSessionWithPlatform() {
            Map<String, Object> sessionData = Map.of(
                    "sessionId", "session-123",
                    "qrContent", "qr-data",
                    "status", "PENDING_SCAN"
            );
            when(qrSessionService.createSession("web")).thenReturn(sessionData);

            QrSessionCreateRequest request = new QrSessionCreateRequest("web");
            ResponseEntity<Map<String, Object>> response = controller.createSession(request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("sessionId", "session-123");
            assertThat(response.getBody()).containsEntry("status", "PENDING_SCAN");
        }

        @Test
        @DisplayName("Should default to unknown platform when request is null")
        void shouldDefaultToUnknownPlatform() {
            Map<String, Object> sessionData = Map.of("sessionId", "session-456", "status", "PENDING_SCAN");
            when(qrSessionService.createSession("unknown")).thenReturn(sessionData);

            ResponseEntity<Map<String, Object>> response = controller.createSession(null);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("sessionId", "session-456");
        }
    }

    @Nested
    @DisplayName("Get Session")
    class GetSession {

        @Test
        @DisplayName("Should return session status")
        void shouldReturnSessionStatus() {
            Map<String, Object> sessionData = Map.of("sessionId", "session-123", "status", "PENDING_SCAN");
            when(qrSessionService.getSession("session-123")).thenReturn(sessionData);

            ResponseEntity<Map<String, Object>> response = controller.getSession("session-123");

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("status", "PENDING_SCAN");
        }
    }

    @Nested
    @DisplayName("Approve Session")
    class ApproveSession {

        @Test
        @DisplayName("Should approve session for authenticated user")
        void shouldApproveSession() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            Map<String, Object> result = Map.of("status", "APPROVED", "accessToken", "jwt-token");
            when(qrSessionService.approveSession("session-123", userId)).thenReturn(result);

            QrSessionApproveRequest request = new QrSessionApproveRequest("android");
            ResponseEntity<Map<String, Object>> response = controller.approveSession("session-123", request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("status", "APPROVED");
            assertThat(response.getBody()).containsEntry("accessToken", "jwt-token");
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

            QrSessionApproveRequest request = new QrSessionApproveRequest("android");

            assertThatThrownBy(() -> controller.approveSession("session-123", request))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }
}
