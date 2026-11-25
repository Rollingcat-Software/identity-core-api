package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.authorTrial.AuthorTrialException;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialInputSanitizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Error mapping for the trial surface only ({@code assignableTypes}), so the
 * global exception handling of every other controller is untouched. Messages
 * are stable codes, never a stack trace or an upstream body.
 */
@RestControllerAdvice(assignableTypes = AuthorTrialController.class)
@Slf4j
public class AuthorTrialExceptionHandler {

    @ExceptionHandler(AuthorTrialException.class)
    public ResponseEntity<Map<String, Object>> handle(AuthorTrialException e) {
        HttpStatus status = switch (e.kind()) {
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case UNAUTHORIZED -> HttpStatus.UNAUTHORIZED;
            case BAD_REQUEST -> HttpStatus.BAD_REQUEST;
            case CONFLICT -> HttpStatus.CONFLICT;
            case UPSTREAM -> HttpStatus.BAD_GATEWAY;
        };
        if (status == HttpStatus.INTERNAL_SERVER_ERROR) {
            log.error("author-trial failure: {}", e.code(), e);
        }
        return ResponseEntity.status(status).body(body(e.code(), e.getMessage()));
    }

    @ExceptionHandler(AuthorTrialInputSanitizer.TrialRequestInvalidException.class)
    public ResponseEntity<Map<String, Object>> handleInvalid(AuthorTrialInputSanitizer.TrialRequestInvalidException e) {
        return ResponseEntity.badRequest().body(body(e.code(), "Invalid request payload"));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, Object>> handleUnreadable(Exception e) {
        return ResponseEntity.badRequest().body(body("TRIAL_BAD_REQUEST", "Malformed request"));
    }

    private static Map<String, Object> body(String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        if (message != null && !message.isBlank() && !message.equals(code)) {
            body.put("message", message);
        }
        return body;
    }
}