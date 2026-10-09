# kervan-auth

The OAuth 2.1 authorization server of Kervan, the fictional cargo company used
as Mandate's brownfield reference system. It issues the access tokens that
`kervan-voice` (the customer agent) presents to `kervan-mcp` (the MCP resource
server). All data is synthetic.

What it implements:

- `client_credentials` only, with `private_key_jwt` client authentication (ES256).
- Client ID metadata documents (CIMD): a client's id is the URL of its
  metadata document, fetched only from allow-listed hosts.
- Resource indicators (RFC 8707): every token is issued for exactly one
  resource, which becomes the token's `aud` (a string).
- ES256 JWT access tokens (`typ: at+jwt`) and a public JWKS.

The shared contract for all Kervan repositories is `SPEC.md` in the Mandate
repository (`examples/kervan/SPEC.md`). This service implements §3.1–§3.4 and
the logging rules of §6.

## Endpoints

| Method and path | Answer |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata; committed as [`docs/oauth-metadata.json`](docs/oauth-metadata.json) for `ISSUER=http://auth:9000` |
| `GET /jwks.json` | The public signing key, `{"keys": [{"kty": "EC", "crv": "P-256", "kid", "alg": "ES256", "use": "sig", …}]}` |
| `POST /token` | `application/x-www-form-urlencoded` token request (below) |
| `GET /health` | `{"status": "ok"}` |

### Token request

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=http://voice:7000/client-metadata.json
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<ES256 JWT: iss = sub = client_id, aud = token endpoint, exp ≤ 60 s, jti>
&scope=shipments:read tickets:write
&resource=http://mcp:3001/mcp
```

The server checks, in order:

1. The request is well formed (`invalid_request`), the grant is
   `client_credentials` (`unsupported_grant_type`), and the client uses
   `private_key_jwt` (`invalid_client`).
2. Exactly one `resource`, listed in `ALLOWED_RESOURCES` (`invalid_target`).
3. The client metadata document: its host is in `CIMD_ALLOWED_HOSTS`; it is
   fetched without redirects within 2 s and cached for 60 s; its `client_id`
   equals the URL it was fetched from and it holds public keys in `jwks`
   (`invalid_client`); if it lists `grant_types`, they include
   `client_credentials` (`unauthorized_client`).
4. The assertion: ES256, signed by a key in the document's `jwks`,
   `iss = sub = client_id`, `aud` = the token endpoint, not expired, `exp` at
   most 60 s ahead, and a `jti` not seen before (`invalid_client`).
5. Every requested scope is in the document's `scope` and in
   `scopes_supported` (`invalid_scope`). Without `scope`, the client gets every
   supported scope its document lists.

Errors are RFC 6749 JSON, `{"error": "...", "error_description": "..."}`, with
status 401 for `invalid_client` and 400 otherwise.

Success:

```json
{"access_token": "…", "token_type": "Bearer", "expires_in": 300, "scope": "shipments:read tickets:write"}
```

The access token's claims are `iss` (`ISSUER`), `sub` and `client_id` (the
client id), `aud` (the resource, a string), `scope`, `iat`, `exp` and `jti`;
its header carries the signing key's `kid`.

## Configuration

Environment only. The defaults are the compose values, so the compose service
needs nothing else.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `9000` | Listen port |
| `ISSUER` | `http://auth:9000` | `iss` of every token and of the metadata; endpoint URLs are built from it |
| `ALLOWED_RESOURCES` | `http://mcp:3001/mcp` | Comma-separated resource indicators tokens may be issued for |
| `CIMD_ALLOWED_HOSTS` | `voice` | Comma-separated hosts client metadata documents may be fetched from. `host` matches any port, `host:port` only that port |
| `TOKEN_TTL_SECONDS` | `300` | Access token lifetime |
| `LOG_FILE` | unset | Also append each log line to this file |
| `SIGNING_KEY_FILE` | unset | PEM (PKCS#8) EC P-256 private key. Unset: a key is generated at start and kept in memory |

With a generated key, every restart changes the `kid`; resource servers
re-fetch the JWKS.

## Logs

One JSON object per line on stdout (and `LOG_FILE`), with `ts`, `level`,
`service: "auth"` and `msg`, plus `trace_id` (from a W3C `traceparent` header,
or fresh), `method`, `path`, `status`, `duration_ms` and, for token requests,
`client_id`, `resource`, `scope` or `error`. Assertions, tokens and keys are
never logged.

## Running

```sh
npm ci
npm run build
npm start          # node dist/main.js
npm test           # vitest
```

With Docker:

```sh
docker build -t kervan-auth .
docker run --rm -p 9000:9000 kervan-auth
curl localhost:9000/health
```

The Dockerfile follows the Kervan rule for building candidate code without
network (SPEC §11): dependencies come from `package-lock.json` with
`npm ci --ignore-scripts`, and the compile step runs with `--network=none`.
The image runs as the unprivileged `node` user.

## How it fits Kervan

```text
voice ──(client_credentials, CIMD)──▶ auth
voice ──(MCP, Bearer JWT)──▶ mcp ──(JWKS)──▶ auth
```

`kervan-voice` serves its metadata document at
`http://voice:7000/client-metadata.json` and asks for a token for
`http://mcp:3001/mcp`. `kervan-mcp` verifies tokens against
`http://auth:9000/jwks.json` and requires `iss = http://auth:9000` and
`aud = http://mcp:3001/mcp` exactly. The system model in `kervan-system` names
this service's interface `TokenIssuance` (protocol `oauth`), and
`docs/oauth-metadata.json` is the spec file that contract checks compare; a
test asserts the running server serves exactly that document.
