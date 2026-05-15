# Go net/http

适用场景：Go API 服务或网关使用 Keylo JWKS 本地验签。

## 1. 依赖

```bash
go get github.com/MicahParks/keyfunc/v3
go get github.com/golang-jwt/jwt/v5
```

## 2. 中间件

```go
package keyloauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const claimsKey contextKey = "keylo_claims"

type Claims struct {
	Scope     []string `json:"scope"`
	Role      []string `json:"role"`
	TokenType string   `json:"token_type"`
	UID       string   `json:"uid,omitempty"`
	jwt.RegisteredClaims
}

func NewMiddleware(jwksURL, issuer, audience string, requiredScope string) (func(http.Handler) http.Handler, error) {
	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(header, "Bearer ")
			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, jwks.Keyfunc,
				jwt.WithIssuer(issuer),
				jwt.WithAudience(audience),
			)
			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			if claims.TokenType != "access" {
				http.Error(w, "invalid token type", http.StatusForbidden)
				return
			}
			if requiredScope != "" && !has(claims.Scope, requiredScope) {
				http.Error(w, "insufficient scope", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func FromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	return claims, ok
}

func has(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
```

## 3. 使用

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"

	"example.com/app/keyloauth"
)

func main() {
	auth, err := keyloauth.NewMiddleware(
		"http://127.0.0.1:2345/.well-known/jwks.json",
		"keylo",
		"inventory-svc",
		"read",
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/items", auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := keyloauth.FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject": claims.Subject,
			"user_id": claims.UID,
			"items":   []string{},
		})
	})))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## 4. 校验要点

- `issuer` 与 Keylo `JWT_ISSUER` 一致
- `audience` 是当前资源服务 ID
- 普通业务接口只接受 `token_type=access`
- 用 `scope` 做接口级授权
- JWKS 客户端应支持缓存和自动刷新
