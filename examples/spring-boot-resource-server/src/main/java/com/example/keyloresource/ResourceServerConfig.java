package com.example.keyloresource;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;

@Configuration
public class ResourceServerConfig {
    /** Verifies issuer and audience before any controller can forward a token to Keylo. */
    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer,
            @Value("${keylo.required-audience}") String requiredAudience
    ) {
        JwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
        if (!(decoder instanceof NimbusJwtDecoder nimbusDecoder)) {
            throw new IllegalStateException("Keylo issuer did not provide a Nimbus JWT decoder");
        }
        nimbusDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer), audienceValidator(requiredAudience)));
        return nimbusDecoder;
    }

    /** Requires the resource service's configured audience instead of trusting any Keylo token. */
    private OAuth2TokenValidator<Jwt> audienceValidator(String requiredAudience) {
        return token -> token.getAudience().contains(requiredAudience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Required audience is missing", null));
    }

    @Bean
    AuthorizationDecisionTransport authorizationDecisionTransport(
            @Value("${keylo.authorization-base-url}") String authorizationBaseUrl
    ) {
        RestClient client = RestClient.builder().baseUrl(authorizationBaseUrl).build();
        return (bearerToken, permission) -> client.post()
                .uri("/v1/authorize/check")
                .header(HttpHeaders.AUTHORIZATION, bearerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("permission", permission))
                .retrieve()
                .body(KeyloAuthorizationDecision.class);
    }

    @Bean
    KeyloAuthorizationClient keyloAuthorizationClient(AuthorizationDecisionTransport transport) {
        return new KeyloAuthorizationClient(transport);
    }

    /** Keeps health public while forcing every API request through JWT authentication. */
    @Bean
    SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }
}
