package com.example.keyloresource;

/** Sends one final permission decision request to Keylo for a verified bearer token. */
@FunctionalInterface
public interface AuthorizationDecisionTransport {
    KeyloAuthorizationDecision check(String bearerToken, String permission);
}
