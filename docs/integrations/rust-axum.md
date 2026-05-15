# Rust Axum

适用场景：Rust/Axum 资源服务消费 Keylo JWT，并使用 JWKS 本地验签。

## 1. 依赖

```toml
[dependencies]
axum = "0.8"
jsonwebtoken = "10"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

## 2. Claims 与状态

```rust
use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct KeyloAuthState {
    pub issuer: String,
    pub audience: String,
    pub jwks: Arc<JwkSet>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyloClaims {
    pub sub: String,
    pub uid: Option<String>,
    pub iss: String,
    pub aud: String,
    pub scope: Vec<String>,
    pub role: Vec<String>,
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}
```

## 3. Extractor

```rust
impl FromRequestParts<KeyloAuthState> for KeyloClaims {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &KeyloAuthState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let token = bearer.token();
        let header = decode_header(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
        let kid = header.kid.ok_or(StatusCode::UNAUTHORIZED)?;
        let jwk = state
            .jwks
            .find(&kid)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| StatusCode::UNAUTHORIZED)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[state.issuer.as_str()]);
        validation.set_audience(&[state.audience.as_str()]);

        let claims = decode::<KeyloClaims>(token, &key, &validation)
            .map_err(|_| StatusCode::UNAUTHORIZED)?
            .claims;

        if claims.token_type != "access" {
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(claims)
    }
}
```

## 4. 使用

```rust
use axum::{routing::get, Json, Router};
use serde_json::json;

async fn list_items(claims: KeyloClaims) -> Result<Json<serde_json::Value>, StatusCode> {
    if !claims.scope.iter().any(|scope| scope == "read") {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(json!({
        "subject": claims.sub,
        "user_id": claims.uid,
        "items": []
    })))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keylo_base_url = "http://127.0.0.1:2345";
    let jwks: JwkSet = reqwest::get(format!("{}/.well-known/jwks.json", keylo_base_url))
        .await?
        .json()
        .await?;

    let state = KeyloAuthState {
        issuer: "keylo".to_string(),
        audience: "inventory-svc".to_string(),
        jwks: Arc::new(jwks),
    };

    let app = Router::new()
        .route("/api/items", get(list_items))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## 5. 生产建议

- JWKS 应缓存，并在 `kid` 不匹配或验签失败时刷新。
- 每个资源服务固定校验自己的 `audience`。
- 接口授权优先使用 `scope`，粗粒度能力可结合 `role`。
- 高敏接口可以在本地验签后叠加 Keylo 内省。
