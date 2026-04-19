package com.fivucsas.identity.domain.exception;

import org.springframework.http.HttpStatus;

/**
 * OAuth 2.0 protocol error carrying an explicit HTTP status.
 *
 * <p>Introduced 2026-04-19 (audit BE-M2). The token endpoint previously used
 * {@link IllegalArgumentException} for every failure mode and the controller
 * mapped them all to HTTP 400. Some OAuth2 errors (e.g. missing credentials
 * for a confidential client) are RFC 6749 §5.2 {@code invalid_client} and
 * MUST return 401 Unauthorized.
 */
public class OAuth2Exception extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    public OAuth2Exception(HttpStatus status, String errorCode, String message) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    public OAuth2Exception(HttpStatus status, String message) {
        this(status, mapStatusToErrorCode(status), message);
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getErrorCode() {
        return errorCode;
    }

    private static String mapStatusToErrorCode(HttpStatus status) {
        if (status == HttpStatus.UNAUTHORIZED) return "invalid_client";
        if (status == HttpStatus.BAD_REQUEST) return "invalid_request";
        return "server_error";
    }
}
