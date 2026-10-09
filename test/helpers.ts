import { randomUUID } from "node:crypto";
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";
import { loadConfig } from "../src/config.js";
import { loadSigningKey, type SigningKey } from "../src/keys.js";
import { createLogger, type Sink } from "../src/log.js";
import { createApp, type AppOptions } from "../src/server.js";
import { JWT_BEARER } from "../src/token.js";

export const ISSUER = "http://auth:9000";
export const TOKEN_ENDPOINT = `${ISSUER}/token`;
export const RESOURCE = "http://mcp:3001/mcp";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function close(server: Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

export interface AuthServer {
  url: string;
  key: SigningKey;
  lines: string[];
  close(): Promise<void>;
}

export async function startAuth(
  env: Record<string, string> = {},
  opts: Partial<Omit<AppOptions, "config" | "key" | "logger">> & { sinks?: Sink[] } = {},
): Promise<AuthServer> {
  const config = loadConfig({ ISSUER, CIMD_ALLOWED_HOSTS: "127.0.0.1", ...env });
  const key = await loadSigningKey(undefined);
  const lines: string[] = [];
  const { sinks = [], ...appOpts } = opts;
  const logger = createLogger([(line) => lines.push(line), ...sinks]);
  const server = createApp({ config, key, logger, ...appOpts });
  const url = await listen(server);
  return { url, key, lines, close: () => close(server) };
}

/** A stand-in for kervan-voice: serves client metadata documents and counts fetches. */
export interface CimdHost {
  origin: string;
  hits: Map<string, number>;
  route(path: string, handler: RequestListener): void;
  close(): Promise<void>;
}

export async function startCimdHost(): Promise<CimdHost> {
  const routes = new Map<string, RequestListener>();
  const hits = new Map<string, number>();
  const server = createServer((req, res) => {
    const path = req.url ?? "/";
    hits.set(path, (hits.get(path) ?? 0) + 1);
    const handler = routes.get(path);
    if (handler) return handler(req, res);
    res.writeHead(404).end();
  });
  const origin = await listen(server);
  return { origin, hits, route: (p, h) => routes.set(p, h), close: () => close(server) };
}

export function serveJson(body: unknown): RequestListener {
  return (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
  };
}

export interface TestClient {
  clientId: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

export async function makeClient(clientId: string, kid = "client-key-1"): Promise<TestClient> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  return { clientId, privateKey, publicJwk };
}

export function metadataDocument(client: TestClient, overrides: Record<string, unknown> = {}) {
  return {
    client_id: client.clientId,
    client_name: "Kervan customer agent",
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "private_key_jwt",
    scope: "shipments:read deliveries:write tickets:write help:read",
    jwks: { keys: [client.publicJwk] },
    ...overrides,
  };
}

export interface AssertionOptions {
  iss?: string;
  sub?: string;
  aud?: string;
  jti?: string;
  /** Seconds relative to now. */
  iat?: number;
  exp?: number;
  key?: CryptoKey;
  kid?: string;
}

export async function makeAssertion(client: TestClient, o: AssertionOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: o.kid ?? (client.publicJwk.kid as string) })
    .setIssuer(o.iss ?? client.clientId)
    .setSubject(o.sub ?? client.clientId)
    .setAudience(o.aud ?? TOKEN_ENDPOINT)
    .setIssuedAt(now + (o.iat ?? 0))
    .setExpirationTime(now + (o.exp ?? 60))
    .setJti(o.jti ?? randomUUID())
    .sign(o.key ?? client.privateKey);
}

export async function tokenParams(client: TestClient, extra: Record<string, string | string[] | null> = {}) {
  const base: Record<string, string | string[] | null> = {
    grant_type: "client_credentials",
    client_id: client.clientId,
    client_assertion_type: JWT_BEARER,
    client_assertion: await makeAssertion(client),
    scope: "shipments:read tickets:write",
    resource: RESOURCE,
    ...extra,
  };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(base)) {
    if (v === null) continue;
    for (const one of Array.isArray(v) ? v : [v]) params.append(k, one);
  }
  return params;
}

export async function postToken(auth: AuthServer, params: URLSearchParams, contentType = "application/x-www-form-urlencoded") {
  const res = await fetch(`${auth.url}/token`, {
    method: "POST",
    headers: { "content-type": contentType },
    body: params.toString(),
  });
  return { status: res.status, headers: res.headers, body: (await res.json()) as Record<string, unknown> };
}
