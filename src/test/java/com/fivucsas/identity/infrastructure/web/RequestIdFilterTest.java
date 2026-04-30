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
        request.addHeader(RequestIdFilter.HEADER_NAME, "abc-123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Capture the MDC value while the chain is executing.
        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(RequestIdFilter.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isEqualTo("abc-123");
        assertThat(response.getHeader(RequestIdFilter.HEADER_NAME)).isEqualTo("abc-123");
        // Cleared after the filter returns.
        assertThat(MDC.get(RequestIdFilter.MDC_KEY)).isNull();
    }

    @Test
    void missingHeaderTriggersUuidGeneration() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        String[] inFlight = new String[1];
        FilterChain chain = (req, res) -> inFlight[0] = MDC.get(RequestIdFilter.MDC_KEY);

        filter.doFilter(request, response, chain);

        assertThat(inFlight[0]).isNotBlank();
        // RFC 4122 UUID string: 36 chars, four hyphens.
        assertThat(inFlight[0]).hasSize(36);
        assertThat(inFlight[0].chars().filter(c -> c == '-').count()).isEqualTo(4L);
        assertThat(response.getHeader(RequestIdFilter.HEADER_NAME)).isEqualTo(inFlight[0]);
    }

    @Test
    void blankHeaderTriggersUuidGeneration() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(RequestIdFilter.HEADER_NAME, "   ");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String echoed = response.getHeader(RequestIdFilter.HEADER_NAME);
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

        assertThat(MDC.get(RequestIdFilter.MDC_KEY)).isNull();
    }

    @Test
    void chainIsInvokedExactlyOnce() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
