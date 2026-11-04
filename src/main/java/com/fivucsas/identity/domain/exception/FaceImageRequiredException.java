package com.fivucsas.identity.domain.exception;

/**
 * Gap Ü2: a client-computed face embedding was refused because
 * {@code FaceEmbeddingLivenessPolicy} is ENFORCE for the tenant. An embedding
 * carries no frame, so bio cannot run liveness on it; the client must enroll with
 * an image instead (multipart {@code /api/v1/biometric/enroll/{userId}}).
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler} to
 * HTTP 409 with {@code code}, {@code error} and {@code errorCode} all set to
 * {@code FACE_IMAGE_REQUIRED}.
 */
public class FaceImageRequiredException extends DomainException {

    public static final String ERROR_CODE = "FACE_IMAGE_REQUIRED";

    public FaceImageRequiredException() {
        super("Face enrollment requires an image capture", ERROR_CODE);
    }
}
