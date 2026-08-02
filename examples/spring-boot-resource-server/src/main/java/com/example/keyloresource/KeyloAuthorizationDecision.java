package com.example.keyloresource;

/** Minimal stable fields returned by Keylo's /v1/authorize/check endpoint. */
public record KeyloAuthorizationDecision(boolean allowed, String decision, String reason) {
}
