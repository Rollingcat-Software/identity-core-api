package com.fivucsas.identity.application.service.authorTrial;

/**
 * Checked failure of the trial surface with a stable client code and a status
 * family. The controller advice maps the family to an HTTP status:
 * NOT_FOUND -> 404, UNAUTHORIZED -> 401, BAD_REQUEST -> 400, CONFLICT -> 409,
 * UPSTREAM -> 502.
 */
public class AuthorTrialException extends RuntimeException {

    public enum Kind { NOT_FOUND, UNAUTHORIZED, BAD_REQUEST, CONFLICT, UPSTREAM }

    private final Kind kind;
    private final String code;

    public AuthorTrialException(Kind kind, String code, String message) {
        super(message == null || message.isBlank() ? code : message);
        this.kind = kind;
        this.code = code;
    }

    public Kind kind() {
        return kind;
    }

    public String code() {
        return code;
    }

    public static AuthorTrialException notFound(String code) {
        return new AuthorTrialException(Kind.NOT_FOUND, code, code);
    }

    public static AuthorTrialException unauthorized(String code) {
        return new AuthorTrialException(Kind.UNAUTHORIZED, code, code);
    }

    public static AuthorTrialException badRequest(String code, String message) {
        return new AuthorTrialException(Kind.BAD_REQUEST, code, message);
    }

    public static AuthorTrialException conflict(String code, String message) {
        return new AuthorTrialException(Kind.CONFLICT, code, message);
    }

    public static AuthorTrialException upstream(String code, String message) {
        return new AuthorTrialException(Kind.UPSTREAM, code, message);
    }
}