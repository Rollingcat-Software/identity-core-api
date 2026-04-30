package com.fivucsas.identity.infrastructure.web;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RequestIdFilterTest {

    private final RequestIdFilter filter = new RequestIdFilter();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void inboundRequestIdHeaderIsHonoredAndEchoed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, "abc-123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Capture the MDC value while the chain is executing.
        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isEqualTo("abc-123");
        assertThat(response.getHeader(CorrelationId.HEADER_NAME)).isEqualTo("abc-123");
        // Cleared after the filter returns.
        assertThat(MDC.get(CorrelationId.MDC_KEY)).isNull();
    }

    @Test
    void missingHeaderTriggersUuidGeneration() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isNotBlank();
        // RFC 4122 UUID string: 36 chars, four hyphens.
        assertThat(inFlight[0]).hasSize(36);
        assertThat(inFlight[0].chars().filter(c -> c == '-').count()).isEqualTo(4L);
        assertThat(response.getHeader(CorrelationId.HEADER_NAME)).isEqualTo(inFlight[0]);
    }

    @Test
    void blankHeaderTriggersUuidGeneration() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, "   ");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String echoed = response.getHeader(CorrelationId.HEADER_NAME);
        assertThat(echoed).isNotBlank();
        assertThat(echoed.trim()).isNotEqualTo("");
    }

    @Test
    void mdcClearedEvenWhenChainThrows() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain throwingChain = (req, res) -> {
            throw new RuntimeException("boom");
        };

        try {
            filter.doFilter(request, response, throwingChain);
        } catch (RuntimeException expected) {
            // ignore
        }

        assertThat(MDC.get(CorrelationId.MDC_KEY)).isNull();
    }

    @Test
    void chainIsInvokedExactlyOnce() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    // -------------------------------------------------------------------
    // Input-validation / log-forging defence
    // -------------------------------------------------------------------

    @Test
    void crlfInjectionAttemptIsRejectedAndReplacedWithUuid() throws Exception {
        // Classic HTTP response-splitting / log-forging payload.
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, "abc\r\nSet-Cookie: pwn=1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        // The malicious value must NOT be echoed back or land in MDC.
        assertThat(inFlight[0]).doesNotContain("\r", "\n", "Set-Cookie");
        // Replaced with a fresh UUID (36 chars, 4 hyphens).
        assertThat(inFlight[0]).hasSize(36);
        assertThat(response.getHeader(CorrelationId.HEADER_NAME)).isEqualTo(inFlight[0]);
    }

    @Test
    void overlongHeaderValueIsRejectedAndReplacedWithUuid() throws Exception {
        String overlong = "a".repeat(CorrelationId.MAX_LENGTH + 1);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, overlong);
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isNotEqualTo(overlong);
        assertThat(inFlight[0]).hasSize(36);
    }

    @Test
    void disallowedCharactersAreRejectedAndReplacedWithUuid() throws Exception {
        // Spaces, dots, slashes, quotes — none are in the allow-list.
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, "abc 123/../\"x\"");
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).hasSize(36);
        assertThat(inFlight[0].chars().filter(c -> c == '-').count()).isEqualTo(4L);
    }

    @Test
    void uuidHeaderValueIsAcceptedUnchanged() throws Exception {
        String inboundUuid = "11111111-2222-3333-4444-555555555555";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, inboundUuid);
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isEqualTo(inboundUuid);
        assertThat(response.getHeader(CorrelationId.HEADER_NAME)).isEqualTo(inboundUuid);
    }

    @Test
    void shortAlphanumericIdIsAcceptedUnchanged() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(CorrelationId.HEADER_NAME, "req_42-A");
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(CorrelationId.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isEqualTo("req_42-A");
        assertThat(response.getHeader(CorrelationId.HEADER_NAME)).isEqualTo("req_42-A");
    }
}
