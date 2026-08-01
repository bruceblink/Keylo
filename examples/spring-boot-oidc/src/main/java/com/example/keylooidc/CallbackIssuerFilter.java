package com.example.keylooidc;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Binds Keylo's authorization response to the issuer discovered by this client.
 * The filter runs before Spring exchanges a callback code and rejects a missing or substituted iss.
 */
public final class CallbackIssuerFilter extends OncePerRequestFilter {
    private static final String CALLBACK_PATH = "/login/oauth2/code/keylo";

    private final String expectedIssuer;

    public CallbackIssuerFilter(String expectedIssuer) {
        this.expectedIssuer = expectedIssuer;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (CALLBACK_PATH.equals(request.getRequestURI())
                && !expectedIssuer.equals(request.getParameter("iss"))) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "OIDC callback issuer is missing or invalid");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
