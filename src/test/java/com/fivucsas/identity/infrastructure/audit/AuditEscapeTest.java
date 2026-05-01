package com.fivucsas.identity.infrastructure.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuditEscape: HTML escape contract")
class AuditEscapeTest {

    @Nested
    @DisplayName("escape(String)")
    class Escape {

        @Test
        @DisplayName("Null input returns null (no NPE)")
        void nullReturnsNull() {
            assertThat(AuditEscape.escape(null)).isNull();
        }

        @Test
        @DisplayName("Empty string passes through unchanged")
        void emptyPassesThrough() {
            assertThat(AuditEscape.escape("")).isEqualTo("");
        }

        @Test
        @DisplayName("String without special chars is returned by reference (fast path)")
        void noSpecialCharsReturnsSameReference() {
            String input = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) safe text 0-9 a-z";
            // Allocation-free fast path: same reference, not just equal contents.
            assertThat(AuditEscape.escape(input)).isSameAs(input);
        }

        @Test
        @DisplayName("Ampersand is escaped to &amp;")
        void ampersand() {
            assertThat(AuditEscape.escape("Tom & Jerry"))
                    .isEqualTo("Tom &amp; Jerry");
        }

        @Test
        @DisplayName("Less-than is escaped to &lt;")
        void lessThan() {
            assertThat(AuditEscape.escape("a < b"))
                    .isEqualTo("a &lt; b");
        }

        @Test
        @DisplayName("Greater-than is escaped to &gt;")
        void greaterThan() {
            assertThat(AuditEscape.escape("a > b"))
                    .isEqualTo("a &gt; b");
        }

        @Test
        @DisplayName("Double quote is escaped to &quot;")
        void doubleQuote() {
            assertThat(AuditEscape.escape("say \"hi\""))
                    .isEqualTo("say &quot;hi&quot;");
        }

        @Test
        @DisplayName("Single quote is escaped to &#39;")
        void singleQuote() {
            assertThat(AuditEscape.escape("it's"))
                    .isEqualTo("it&#39;s");
        }

        @Test
        @DisplayName("All five special chars together — typical XSS payload")
        void scriptTagPayload() {
            assertThat(AuditEscape.escape("<script>alert('xss')</script>"))
                    .isEqualTo("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
        }

        @Test
        @DisplayName("Image-onerror payload escapes correctly")
        void imageOnerror() {
            assertThat(AuditEscape.escape("<img src=x onerror=\"alert(1)\">"))
                    .isEqualTo("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
        }

        @Test
        @DisplayName("Already-escaped entity is double-encoded — by design (idempotent escape)")
        void doubleEncodingByDesign() {
            // Audit-log writers don't know if the upstream caller escaped; we
            // always escape on the way in. A literal "&amp;" supplied by an
            // attacker should become "&amp;amp;" so the renderer still sees
            // the original intent. Confirms behavior.
            assertThat(AuditEscape.escape("&amp;"))
                    .isEqualTo("&amp;amp;");
        }

        @Test
        @DisplayName("Non-ASCII characters pass through unchanged (no UTF mangling)")
        void unicodePassesThrough() {
            assertThat(AuditEscape.escape("Türkçe naïve résumé 日本語"))
                    .isEqualTo("Türkçe naïve résumé 日本語");
        }
    }

    @Nested
    @DisplayName("escapeIfString(Object)")
    class EscapeIfString {

        @Test
        @DisplayName("Null passes through unchanged")
        void nullPassesThrough() {
            assertThat(AuditEscape.escapeIfString(null)).isNull();
        }

        @Test
        @DisplayName("String value is escaped")
        void stringIsEscaped() {
            assertThat(AuditEscape.escapeIfString("<b>x</b>"))
                    .isEqualTo("&lt;b&gt;x&lt;/b&gt;");
        }

        @Test
        @DisplayName("Integer passes through unchanged")
        void integerPassesThrough() {
            Integer v = 42;
            assertThat(AuditEscape.escapeIfString(v)).isSameAs(v);
        }

        @Test
        @DisplayName("UUID passes through unchanged")
        void uuidPassesThrough() {
            UUID v = UUID.fromString("00000000-0000-0000-0000-000000000001");
            assertThat(AuditEscape.escapeIfString(v)).isSameAs(v);
        }

        @Test
        @DisplayName("List passes through unchanged (caller's responsibility for nested escape)")
        void listPassesThrough() {
            List<String> v = List.of("a", "<b>");
            assertThat(AuditEscape.escapeIfString(v)).isSameAs(v);
        }

        @Test
        @DisplayName("Map passes through unchanged")
        void mapPassesThrough() {
            Map<String, Object> v = Map.of("k", "<v>");
            assertThat(AuditEscape.escapeIfString(v)).isSameAs(v);
        }

        @Test
        @DisplayName("Boolean passes through unchanged")
        void booleanPassesThrough() {
            Boolean v = Boolean.TRUE;
            assertThat(AuditEscape.escapeIfString(v)).isSameAs(v);
        }
    }
}
