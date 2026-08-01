package com.example.keylooidc;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@RestController
public class SecurityConfig {
    /**
     * Protect browser routes with Spring's standard OIDC client. Spring stores and checks state,
     * applies PKCE where appropriate, and verifies the ID Token using provider discovery and JWKS.
     */
    @Bean
    SecurityFilterChain applicationSecurity(
            HttpSecurity http,
            @Value("${spring.security.oauth2.client.provider.keylo.issuer-uri}") String issuer
    ) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new CallbackIssuerFilter(issuer), OAuth2LoginAuthenticationFilter.class)
                .oauth2Login(Customizer.withDefaults())
                .logout(logout -> logout.logoutSuccessUrl("/"))
                .build();
    }

    /** Returns only verified OIDC claims that the browser application needs after login. */
    @GetMapping("/")
    Map<String, Object> profile(@AuthenticationPrincipal OidcUser user) {
        return Map.of(
                "sub", user.getSubject(),
                "name", user.getFullName() == null ? "" : user.getFullName(),
                "email", user.getEmail() == null ? "" : user.getEmail()
        );
    }
}
