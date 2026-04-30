package com.fivucsas.identity.infrastructure.audit;

/**
 * Defense-in-depth HTML escaping for strings persisted to {@code audit_logs}.
 *
 * <p>Audit rows are rendered in tenant-admin UI tables. The current React frontend
 * escapes by default, but a future export, plugin, or non-JSX renderer could
 * accidentally render raw values. To keep the database row safe regardless of
 * downstream renderer, user-supplied strings (display names, user-agent strings,
 * error messages) are HTML-escaped on the way in.</p>
 *
 * <p>Implemented inline rather than pulling in {@code commons-text} because
 * {@code commons-text} is not currently on the classpath and the rules we
 * need are simple. Escapes the same five characters that
 * {@code StringEscapeUtils.escapeHtml4} treats as critical for HTML body
 * context: {@code & < > " '}.</p>
 *
 * <p>Note: numeric/UUID/Map values flowing through {@code metadata} are
 * already JSON-encoded by Hibernate's JSONB mapper, which itself escapes
 * embedded HTML. The risk surface is plain {@code String} fields like
 * {@code error_message}, {@code endpoint}, and string-typed metadata
 * parameters — which is what this helper covers.</p>
 */
public final class AuditEscape {

    private AuditEscape() {
        // utility
    }

    /**
     * Escapes the five HTML special characters in {@code value}. Returns
     * {@code null} if input is {@code null}.
     */
    public static String escape(String value) {
        if (value == null) {
            return null;
        }
        // Avoid allocating a StringBuilder for the common case of no special chars.
        if (!needsEscaping(value)) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * If the input is a {@link String}, returns the HTML-escaped form.
     * Anything else is passed through unchanged so that integers, UUIDs,
     * collections, and arbitrary structured payloads keep their original
     * type when persisted to the JSONB metadata column.
     */
    public static Object escapeIfString(Object value) {
        if (value instanceof String s) {
            return escape(s);
        }
        return value;
    }

    private static boolean needsEscaping(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '&' || c == '<' || c == '>' || c == '"' || c == '\'') {
                return true;
            }
        }
        return false;
    }
}
