# JWT signing-key rotation runbook

Keylo signs new JWTs with one active RSA key and keeps the previous key as a
passive verification key for a bounded overlap window. The public JWKS endpoint
publishes the active key and every live passive key; private key material stays
on the Keylo host and is never returned by an API.

## Configuration

The active key is loaded at startup from `JWT_PRIVATE_KEY_PATH` and
`JWT_PUBLIC_KEY_PATH` (or the corresponding PEM variables). Managed rotation
also persists the active key id to `JWT_KEY_ID_PATH`.

Optional passive startup files are controlled by:

- `JWT_PASSIVE_PRIVATE_KEY_PATH`
- `JWT_PASSIVE_PUBLIC_KEY_PATH`
- `JWT_PASSIVE_KEY_ID_PATH`
- `JWT_KEY_OVERLAP_SECONDS` (default `300`, allowed range `1..2592000`)

Configure the passive id and public key together. A passive private key is only
needed for rollback. Production deployments must provide persistent active key
files and should back up the active/passive files before maintenance.

## Rotate

Use a platform administrator access token with recent MFA when required by the
deployment policy:

```http
POST /v1/admin/security/jwt-keys/rotate
Authorization: Bearer <platform-admin-token>
Content-Type: application/json

{"key_id":"keylo-rs256-2","overlap_seconds":900}
```

`key_id` is optional; when omitted Keylo generates a unique id. The response
returns the active id, passive ids, and the effective overlap. New tokens use
only the active id. Existing tokens signed by the previous id remain valid
until the overlap expires or the key is retired.

After rotation, verify that `GET /.well-known/jwks.json` contains both ids and
that downstream verifiers refresh their JWKS cache when they see the new `kid`.
The operation writes a `jwt_signing_key.rotated` audit event without private
key material.

## Roll back

Rollback promotes a live passive key back to active and keeps the current
active key passive for the configured overlap:

```http
POST /v1/admin/security/jwt-keys/rollback
Authorization: Bearer <platform-admin-token>
Content-Type: application/json

{"key_id":"keylo-rs256-1"}
```

Rollback requires that the passive key still has private material. It writes a
`jwt_signing_key.rollback` audit event and is safe to repeat only while the
requested key remains in the live passive set.

## Retire

Retire a passive key early when all downstream systems have refreshed JWKS or
when the key must be invalidated immediately:

```http
POST /v1/admin/security/jwt-keys/retire
Authorization: Bearer <platform-admin-token>
Content-Type: application/json

{"key_id":"keylo-rs256-1"}
```

Retirement removes the passive key from runtime verification, deletes its
persistent passive files, and records `jwt_signing_key.retired`. Tokens signed
with the retired key are rejected even if their normal JWT expiry has not been
reached.

## Recovery checklist

1. Confirm the active and passive ids from `/.well-known/jwks.json`.
2. Check the corresponding rotation/rollback/retire audit event.
3. Refresh downstream JWKS caches and retry a token signed with the active key.
4. If the new key is suspected to be invalid, roll back while the previous
   passive key is still live, then retire the problematic key after verification.

Never copy a private key into JWKS, logs, audit details, support tickets, or
third-party services. Consumers should use JWKS for local signature checks and
use `/v1/auth/introspect` or `/v1/service/introspect` only when real-time
revocation is required.
