package com.example.keyloresource;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class KeyloAuthorizationClientTest {
    /** Ensures only Keylo's explicit allow contract reaches the protected resource. */
    @Test
    void acceptsOnlyExplicitAllowDecision() {
        KeyloAuthorizationClient allowed = new KeyloAuthorizationClient(
                (token, permission) -> new KeyloAuthorizationDecision(true, "allow", "permission_granted"));
        KeyloAuthorizationClient denied = new KeyloAuthorizationClient(
                (token, permission) -> new KeyloAuthorizationDecision(true, "deny", "permission_not_bound"));

        assertThat(allowed.isAllowed("Bearer verified-token", "keystone:system:user:list")).isTrue();
        assertThat(denied.isAllowed("Bearer verified-token", "keystone:system:user:list")).isFalse();
        assertThat(allowed.isAllowed("invalid", "keystone:system:user:list")).isFalse();
    }

    @Test
    void deniesWhenKeyloCannotReturnADecision() {
        KeyloAuthorizationClient client = new KeyloAuthorizationClient(
                (token, permission) -> { throw new IllegalStateException("Keylo unavailable"); });

        assertThat(client.isAllowed("Bearer verified-token", "keystone:system:user:list")).isFalse();
    }
}
