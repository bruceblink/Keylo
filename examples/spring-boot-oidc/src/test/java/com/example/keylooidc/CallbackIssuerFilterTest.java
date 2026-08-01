package com.example.keylooidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class CallbackIssuerFilterTest {
    private final CallbackIssuerFilter filter = new CallbackIssuerFilter("https://keylo.example.test");

    /** Verify a callback cannot reach Spring's token exchange unless its RFC 9207 issuer matches. */
    @Test
    void rejectsCallbackWithoutExpectedIssuer() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keylo");
        request.addParameter("iss", "https://other.example.test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void passesCallbackWithExpectedIssuer() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keylo");
        request.addParameter("iss", "https://keylo.example.test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }
}
