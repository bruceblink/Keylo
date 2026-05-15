# Node Express

适用场景：Node.js BFF、API 网关或 Express 资源服务使用 Keylo JWKS 本地验签。

## 1. 依赖

```bash
npm install express jose
```

## 2. 中间件

```js
import express from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";

const keyloBaseUrl = process.env.KEYLO_BASE_URL ?? "http://127.0.0.1:2345";
const issuer = process.env.KEYLO_ISSUER ?? "keylo";
const audience = process.env.KEYLO_AUDIENCE ?? "inventory-svc";
const jwks = createRemoteJWKSet(new URL(`${keyloBaseUrl}/.well-known/jwks.json`));

function requireScope(payload, scope) {
  const scopes = Array.isArray(payload.scope) ? payload.scope : [];
  if (!scopes.includes(scope)) {
    const error = new Error("insufficient_scope");
    error.status = 403;
    throw error;
  }
}

export function keyloAuth(requiredScope) {
  return async (req, res, next) => {
    try {
      const header = req.header("authorization") ?? "";
      const [scheme, token] = header.split(" ");
      if (scheme !== "Bearer" || !token) {
        return res.status(401).json({ error: "missing_token" });
      }

      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience,
      });

      if (payload.token_type !== "access") {
        return res.status(403).json({ error: "token_type_invalid" });
      }

      if (requiredScope) {
        requireScope(payload, requiredScope);
      }

      req.keylo = {
        subject: payload.sub,
        userId: payload.uid,
        scopes: payload.scope ?? [],
        roles: payload.role ?? [],
        claims: payload,
      };

      next();
    } catch (error) {
      const status = error.status ?? 401;
      res.status(status).json({ error: error.message ?? "invalid_token" });
    }
  };
}
```

## 3. 使用

```js
const app = express();

app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

app.get("/api/items", keyloAuth("read"), (req, res) => {
  res.json({
    subject: req.keylo.subject,
    items: [],
  });
});

app.post("/api/items", keyloAuth("write"), (_req, res) => {
  res.status(201).json({ success: true });
});

app.listen(3000);
```

## 4. 高敏接口叠加内省

本地验签通过后，可使用服务 token 调用 Keylo 内省接口。只有注册服务时 `introspection_allowed=true` 的服务 token 才能调用内省。

```js
async function introspectUserToken(serviceToken, userToken) {
  const response = await fetch(`${keyloBaseUrl}/v1/auth/introspect`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${serviceToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ token: userToken }),
  });

  return response.json();
}
```
