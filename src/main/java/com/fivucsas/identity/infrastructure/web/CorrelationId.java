package com.fivucsas.identity.infrastructure.web;

import java.util.regex.Pattern;

/**
 * Correlation-id constants and validation shared between the inbound
 * {@link RequestIdFilter} (which publishes the id on the MDC) and the
 * outbound {@link com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient}
 * (which propagates the id on downstream HTTP calls).
 *
 * <p>Centralising these values here keeps the outbound adapter from
 * importing the inbound web filter — both sides depend only on this
 * neutral constants holder.
 */
public final class CorrelationId {

    /** HTTP header name used on both inbound and outbound requests. */
    public static final String HEADER_NAME = "X-Request-Id";

    /** SLF4J MDC key under which the id is published per request thread. */
    public static final String MDC_KEY = "requestId";

    /** Maximum accepted length for an inbound correlation id. */
    public static final int MAX_LENGTH = 64;

    /**
     * Strict allow-list for inbound correlation ids: alphanumerics, hyphen
     * and underscore, 1–{@value MAX_LENGTH} chars. Rejects whitespace, CR/LF,
     * quotes and any other character that could be used for log forging or
     * response-splitting attacks.
     */
    public static final Pattern VALID_PATTERN =
            Pattern.compile("^[A-Za-z0-9_-]{1," + MAX_LENGTH + "}$");

    private CorrelationId() {
        // utility class — no instances
    }

    /**
     * @return {@code true} if the supplied value is a safe correlation id
     *         that can be echoed into MDC and the response header without
     *         further sanitisation.
     */
    public static boolean isValid(String value) {
        return value != null && VALID_PATTERN.matcher(value).matches();
    }
}
