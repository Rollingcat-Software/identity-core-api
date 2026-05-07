package com.fivucsas.identity.exception;

import com.fivucsas.identity.domain.exception.AccountLockedException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for {@link GlobalExceptionHandler}.
 *
 * <p>Currently focused on the handler added for P0-#5
 * ({@link AccountLockedException}). Other handlers are exercised through the
 * controller integration tests; this file exists primarily to lock down the
 * 423 response contract.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GlobalExceptionHandler Tests")
class GlobalExceptionHandlerTest {

    @Mock
    private HttpServletRequest request;

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    @DisplayName("AccountLockedException → HTTP 423 Locked with structured body and remaining seconds")
    void accountLockedExceptionMapsTo423WithBody() {
        lenient().when(request.getRequestURI()).thenReturn("/api/v1/auth/login");

        long remainingSeconds = 873L;
        AccountLockedException ex = new AccountLockedException(remainingSeconds);

        ResponseEntity<Map<String, Object>> response = handler.handleAccountLocked(ex, request);

        // Status: 423 Locked
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        assertThat(response.getStatusCode().value()).isEqualTo(423);

        // Body shape — must include the contract fields the frontend keys off.
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).containsKeys(
                "timestamp", "status", "error", "errorCode", "message",
                "remainingLockTimeSeconds", "path"
        );
        assertThat(body.get("status")).isEqualTo(423);
        assertThat(body.get("error")).isEqualTo("ACCOUNT_LOCKED");
        assertThat(body.get("errorCode")).isEqualTo("ACCOUNT_LOCKED");
        assertThat(body.get("remainingLockTimeSeconds")).isEqualTo(remainingSeconds);
        assertThat(body.get("path")).isEqualTo("/api/v1/auth/login");
        // The exception's getMessage() interpolates minutes from the seconds.
        assertThat((String) body.get("message")).contains("minute");
    }

    @Test
    @DisplayName("AccountLockedException with zero seconds still returns 423 with errorCode")
    void accountLockedExceptionWithZeroSecondsStillReturns423() {
        lenient().when(request.getRequestURI()).thenReturn("/api/v1/auth/login");

        AccountLockedException ex = new AccountLockedException(0L);

        ResponseEntity<Map<String, Object>> response = handler.handleAccountLocked(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("remainingLockTimeSeconds")).isEqualTo(0L);
        assertThat(response.getBody().get("errorCode")).isEqualTo("ACCOUNT_LOCKED");
    }
}
