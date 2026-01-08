package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.service.AuthenticateUserService;
import com.fivucsas.identity.application.service.LogoutUserService;
import com.fivucsas.identity.application.service.RefreshAccessTokenService;
import com.fivucsas.identity.application.service.RegisterUserService;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.InvalidEmailException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;

/**
 * Unit tests for AuthController.
 *
 * Tests all authentication endpoints with various scenarios:
 * - Registration (success, duplicate email, invalid data)
 * - Login (success, invalid credentials)
 * - Token refresh (success, invalid token)
 * - Logout (success)
 *
 * Uses MockMvc for controller testing and Mockito for mocking services.
 */
@WebMvcTest(AuthController.class)
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false) // Disable security filters for unit tests
@DisplayName("Auth Controller Tests")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private RegisterUserService registerUserService;

    @MockBean
    private AuthenticateUserService authenticateUserService;

    @MockBean
    private RefreshAccessTokenService refreshAccessTokenService;

    @MockBean
    private LogoutUserService logoutUserService;

    // Test Data
    private static final String TEST_EMAIL = "test@fivucsas.com";
    private static final String TEST_PASSWORD = "SecurePassword123!";
    private static final String TEST_FIRST_NAME = "Test";
    private static final String TEST_LAST_NAME = "User";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_REFRESH_TOKEN = "550e8400-e29b-41d4-a716-446655440000";

    // ============== REGISTRATION TESTS ==============

    @Test
    @DisplayName("POST /api/auth/register - Success (201)")
    void testRegister_Success() throws Exception {
        // Arrange
        RegisterUserCommand command = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress("127.0.0.1")
                .userAgent("Test-Agent")
                .build();

        UserResponse userResponse = UserResponse.builder()
                .id("123e4567-e89b-12d3-a456-426614174000")
                .email(TEST_EMAIL)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .status("ACTIVE")
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .build();

        AuthenticationResponse authResponse = AuthenticationResponse.of(
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                userResponse
        );

        when(registerUserService.execute(any(RegisterUserCommand.class)))
                .thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value(TEST_ACCESS_TOKEN))
                .andExpect(jsonPath("$.refreshToken").value(TEST_REFRESH_TOKEN))
                .andExpect(jsonPath("$.user.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.user.firstName").value(TEST_FIRST_NAME))
                .andExpect(jsonPath("$.user.status").value("ACTIVE"));

        verify(registerUserService, times(1)).execute(any(RegisterUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/auth/register - Duplicate Email (409)")
    void testRegister_DuplicateEmail() throws Exception {
        // Arrange
        RegisterUserCommand command = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress("127.0.0.1")
                .userAgent("Test-Agent")
                .build();

        when(registerUserService.execute(any(RegisterUserCommand.class)))
                .thenThrow(new DuplicateEmailException(TEST_EMAIL));

        // Act & Assert
        mockMvc.perform(post("/api/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").exists());

        verify(registerUserService, times(1)).execute(any(RegisterUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/auth/register - Invalid Email Format (400)")
    void testRegister_InvalidEmailFormat() throws Exception {
        // Arrange
        RegisterUserCommand command = RegisterUserCommand.builder()
                .email("invalid-email")
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress("127.0.0.1")
                .userAgent("Test-Agent")
                .build();

        when(registerUserService.execute(any(RegisterUserCommand.class)))
                .thenThrow(new InvalidEmailException("invalid-email"));

        // Act & Assert
        mockMvc.perform(post("/api/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());

        verify(registerUserService, times(1)).execute(any(RegisterUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/auth/register - Missing Required Fields (400)")
    void testRegister_MissingFields() throws Exception {
        // Arrange - Missing email and password
        String invalidJson = "{\"firstName\":\"Test\",\"lastName\":\"User\"}";

        // Act & Assert
        mockMvc.perform(post("/api/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidJson))
                .andExpect(status().isBadRequest());

        verify(registerUserService, never()).execute(any(RegisterUserCommand.class));
    }

    // ============== LOGIN TESTS ==============

    @Test
    @DisplayName("POST /api/auth/login - Success (200)")
    void testLogin_Success() throws Exception {
        // Arrange
        AuthenticateUserCommand command = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress("127.0.0.1")
                .userAgent("Test-Agent")
                .build();

        UserResponse userResponse = UserResponse.builder()
                .id("123e4567-e89b-12d3-a456-426614174000")
                .email(TEST_EMAIL)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .status("ACTIVE")
                .isBiometricEnrolled(true)
                .verificationCount(5)
                .build();

        AuthenticationResponse authResponse = AuthenticationResponse.of(
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                userResponse
        );

        when(authenticateUserService.execute(any(AuthenticateUserCommand.class)))
                .thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value(TEST_ACCESS_TOKEN))
                .andExpect(jsonPath("$.refreshToken").value(TEST_REFRESH_TOKEN))
                .andExpect(jsonPath("$.user.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.user.isBiometricEnrolled").value(true))
                .andExpect(jsonPath("$.user.verificationCount").value(5));

        verify(authenticateUserService, times(1)).execute(any(AuthenticateUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/auth/login - Invalid Credentials (401)")
    void testLogin_InvalidCredentials() throws Exception {
        // Arrange
        AuthenticateUserCommand command = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password("WrongPassword123!")
                .ipAddress("127.0.0.1")
                .userAgent("Test-Agent")
                .build();

        when(authenticateUserService.execute(any(AuthenticateUserCommand.class)))
                .thenThrow(new InvalidCredentialsException());

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists());

        verify(authenticateUserService, times(1)).execute(any(AuthenticateUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/auth/login - Missing Credentials (400)")
    void testLogin_MissingCredentials() throws Exception {
        // Arrange - Missing password
        String invalidJson = "{\"email\":\"test@fivucsas.com\"}";

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidJson))
                .andExpect(status().isBadRequest());

        verify(authenticateUserService, never()).execute(any(AuthenticateUserCommand.class));
    }

    // ============== TOKEN REFRESH TESTS ==============

    @Test
    @DisplayName("POST /api/auth/refresh - Success (200)")
    @WithMockUser
    void testRefreshToken_Success() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"" + TEST_REFRESH_TOKEN + "\"}";

        AuthenticationResponse authResponse = AuthenticationResponse.of(
                "new-access-token",
                "new-refresh-token",
                UserResponse.builder()
                        .id("123")
                        .email(TEST_EMAIL)
                        .firstName(TEST_FIRST_NAME)
                        .lastName(TEST_LAST_NAME)
                        .status("ACTIVE")
                        .build()
        );

        when(refreshAccessTokenService.execute(any()))
                .thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));

        verify(refreshAccessTokenService, times(1)).execute(any());
    }

    @Test
    @DisplayName("POST /api/auth/refresh - Invalid Token (401)")
    @WithMockUser
    void testRefreshToken_InvalidToken() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"invalid-token\"}";

        when(refreshAccessTokenService.execute(any()))
                .thenThrow(new InvalidCredentialsException("Invalid refresh token"));

        // Act & Assert
        mockMvc.perform(post("/api/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists());

        verify(refreshAccessTokenService, times(1)).execute(any());
    }

    // ============== LOGOUT TESTS ==============

    @Test
    @DisplayName("POST /api/auth/logout - Success (200)")
    @WithMockUser(username = TEST_EMAIL)
    void testLogout_Success() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"" + TEST_REFRESH_TOKEN + "\"}";

        doNothing().when(logoutUserService).execute(any());

        // Act & Assert
        mockMvc.perform(post("/api/auth/logout")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());

        verify(logoutUserService, times(1)).execute(any());
    }

    @Test
    @DisplayName("POST /api/auth/logout - Unauthorized (401)")
    void testLogout_Unauthorized() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"" + TEST_REFRESH_TOKEN + "\"}";

        // Act & Assert - No authentication
        mockMvc.perform(post("/api/auth/logout")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isUnauthorized());

        verify(logoutUserService, never()).execute(any());
    }
}
