package com.example.keyloresource;

/**
 * Applies Keylo's final authorization decision after Spring has verified the JWT.
 * Transport failures and malformed credentials deny access so a resource service never upgrades
 * an unavailable authorization service into implicit permission.
 */
public final class KeyloAuthorizationClient {
    private final AuthorizationDecisionTransport transport;

    public KeyloAuthorizationClient(AuthorizationDecisionTransport transport) {
        this.transport = transport;
    }

    public boolean isAllowed(String bearerToken, String permission) {
        if (bearerToken == null || !bearerToken.startsWith("Bearer ") || permission == null || permission.isBlank()) {
            return false;
        }

        try {
            KeyloAuthorizationDecision response = transport.check(bearerToken, permission);
            return response != null && response.allowed() && "allow".equals(response.decision());
        } catch (RuntimeException ignored) {
            return false;
        }
    }
}
