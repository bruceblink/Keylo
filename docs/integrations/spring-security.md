# Spring Security Resource Server

适用场景：Spring Boot 后台、BFF、管理系统或内部 API 服务消费 Keylo 签发的用户 access token。

## 1. 配置

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://keylo.example.com
          jwk-set-uri: https://keylo.example.com/.well-known/jwks.json
```

`issuer-uri` 必须与 Keylo 的 `JWT_ISSUER` 一致。若 `JWT_ISSUER=keylo`，这里也使用 `keylo`；若生产环境使用完整 URL，Keylo 和 Spring 配置需要保持一致。

## 2. Audience 与 Token 类型校验

Spring 的 JWT Resource Server 默认会验签、校验过期时间和 issuer，但业务服务仍应显式校验 `aud`、`token_type` 和 `scope`。

```java
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public final class KeyloJwtAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {
    private final String expectedAudience;

    public KeyloJwtAuthenticationConverter(String expectedAudience) {
        this.expectedAudience = expectedAudience;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        if (!jwt.getAudience().contains(expectedAudience)) {
            throw new IllegalArgumentException("invalid audience");
        }
        if (!"access".equals(jwt.getClaimAsString("token_type"))) {
            throw new IllegalArgumentException("invalid token type");
        }

        List<String> scopes = jwt.getClaimAsStringList("scope");
        Collection<GrantedAuthority> authorities = scopes == null
                ? List.of()
                : scopes.stream()
                        .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                        .collect(Collectors.toList());

        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }
}
```

```java
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Bean
SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health").permitAll()
            .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
            .jwtAuthenticationConverter(
                new KeyloJwtAuthenticationConverter("inventory-svc")
            )
        ));

    return http.build();
}
```

## 3. 接入检查清单

- `jwk-set-uri` 指向 `/.well-known/jwks.json`
- `issuer-uri` 与 Keylo `JWT_ISSUER` 一致
- 每个资源服务固定校验自己的 `aud`
- 普通业务接口只接受 `token_type=access`
- 需要管理能力时校验 `scope=admin` 或业务 scope
- 高敏接口可在本地验签后调用 Keylo 内省端点
