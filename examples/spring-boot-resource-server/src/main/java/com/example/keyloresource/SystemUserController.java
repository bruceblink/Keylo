package com.example.keyloresource;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class SystemUserController {
    private static final String LIST_USERS_PERMISSION = "keystone:system:user:list";

    private final KeyloAuthorizationClient authorizationClient;

    public SystemUserController(KeyloAuthorizationClient authorizationClient) {
        this.authorizationClient = authorizationClient;
    }

    /** Demonstrates a resource endpoint that denies access unless Keylo grants its business permission. */
    @GetMapping("/api/system/users")
    Map<String, Object> listUsers(@RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken) {
        if (!authorizationClient.isAllowed(bearerToken, LIST_USERS_PERMISSION)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Keylo permission denied");
        }
        return Map.of("data", "authorized resource response");
    }
}
