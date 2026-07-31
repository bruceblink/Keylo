# Keycloak OIDC Upstream Matrix

This matrix is the executable acceptance baseline for the upstream OIDC portion of the roadmap. It uses a real Keycloak server and does not treat unit tests, a mock IdP, or the HTTP-only fixture as equivalent evidence.

## Fixture

`docker-compose.keycloak-matrix.yml` imports `tests/keycloak/realm/keylo-matrix-realm.json` into Keycloak 26.7.0. The realm defines a confidential `keylo-upstream-matrix` client with Authorization Code Flow and a verified test user. Passwords, client secrets, and Keylo's callback are environment substitutions and are never committed.

The fixture uses `start-dev` and HTTP only to bootstrap the realm. It is not itself an acceptance environment: the matrix requires publicly verifiable HTTPS issuers for both Keylo and Keycloak.

```powershell
$env:KEYCLOAK_MATRIX_ADMIN_PASSWORD = "..."
$env:KEYCLOAK_MATRIX_CLIENT_SECRET = "..."
$env:KEYCLOAK_MATRIX_USER_PASSWORD = "..."
$env:KEYLO_MATRIX_REDIRECT_URI = "https://identity.example.test/v1/upstream/oidc/callback"
docker compose -f docker-compose.keycloak-matrix.yml up -d
```

## Preflight

Run preflight against the HTTPS endpoints that will be used for the actual browser flow:

```powershell
.\scripts\test_keycloak_oidc_matrix_preflight.ps1 `
  -KeyloPublicIssuer "https://identity.example.test" `
  -KeycloakIssuer "https://idp.example.test/realms/keylo-matrix"
```

The script verifies exact Discovery issuer binding, HTTPS endpoints, Authorization Code support, `client_secret_basic`, and RS256. It stores only public Discovery metadata and the current Keylo commit beneath `artifacts/oidc-matrix/`; no secret, authorization code, access token, refresh token, or ID Token is written.

Preflight success means the environment can execute the matrix. It does not mean the browser scenarios passed.

## Scenario Record

For a completed run, record each roadmap scenario as `passed`, `failed`, or `not_executed`, with an HTTP status/result summary only:

| Scenario | Required assertion |
| --- | --- |
| First login | JIT creates one local user and one stable source mapping. |
| Repeat login | Existing user and mapping are reused. |
| UserInfo completion | Matching `sub` may fill missing profile fields only. |
| Email change | Login follows stable upstream `sub`; local email remains unchanged. |
| Disabled Keylo user | Protected access is rejected and refresh sessions are revoked. |
| Disabled identity source | New callback is rejected, source refresh sessions are revoked, and audit records the count. |

TLS, network, or browser automation failure must be recorded as `not_executed`; it must not be reclassified as a unit-test pass.
