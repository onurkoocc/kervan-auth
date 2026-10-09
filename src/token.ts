import { randomUUID } from "node:crypto";
import { SignJWT, createLocalJWKSet, errors, jwtVerify, type JWTPayload } from "jose";
import type { CimdResolver, ClientMetadata } from "./cimd.js";
import { SCOPES_SUPPORTED, type Config } from "./config.js";
import type { SigningKey } from "./keys.js";
import { tokenEndpoint } from "./metadata.js";
import {
  invalidClient,
  invalidRequest,
  invalidScope,
  invalidTarget,
  unsupportedGrantType,
} from "./oauth-error.js";
import type { JtiCache } from "./replay.js";

export const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** The longest client assertion lifetime accepted (SPEC §3.3: exp ≤ 60 s). */
const MAX_ASSERTION_LIFETIME_S = 60;
const CLOCK_SKEW_S = 5;

export interface TokenContext {
  config: Config;
  key: SigningKey;
  cimd: CimdResolver;
  jtis: JtiCache;
  now?: () => number;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

/** What the request log may record about a token request: never the assertion or the token. */
export interface TokenOutcome {
  client_id?: string;
  resource?: string;
  scope?: string;
}

/**
 * Handles one client_credentials request (SPEC §3.3). Throws OAuthError on refusal;
 * `outcome` is filled as the request is understood, for logging.
 */
export async function issueToken(
  params: URLSearchParams,
  ctx: TokenContext,
  outcome: TokenOutcome = {},
): Promise<TokenResponse> {
  for (const name of new Set(params.keys())) {
    if (name !== "resource" && params.getAll(name).length > 1) {
      throw invalidRequest(`parameter ${name} is repeated`);
    }
  }

  const grantType = params.get("grant_type");
  if (!grantType) throw invalidRequest("grant_type is required");
  if (grantType !== "client_credentials") throw unsupportedGrantType("only client_credentials is supported");

  const clientId = params.get("client_id");
  if (!clientId) throw invalidRequest("client_id is required");
  outcome.client_id = clientId;

  if (params.get("client_assertion_type") !== JWT_BEARER) {
    throw invalidClient(`client_assertion_type must be ${JWT_BEARER}`);
  }
  const assertion = params.get("client_assertion");
  if (!assertion) throw invalidClient("client_assertion is required");

  const resource = checkResource(params.getAll("resource"), ctx.config.allowedResources);
  outcome.resource = resource;

  const nowMs = (ctx.now ?? Date.now)();
  const client = await ctx.cimd.resolve(clientId);
  await authenticate(assertion, client, ctx, nowMs);

  const scope = grantScope(params.get("scope"), client.scope);
  outcome.scope = scope;

  const iat = Math.floor(nowMs / 1000);
  const ttl = ctx.config.tokenTtlSeconds;
  const accessToken = await new SignJWT({ scope, client_id: clientId })
    .setProtectedHeader({ alg: "ES256", kid: ctx.key.kid, typ: "at+jwt" })
    .setIssuer(ctx.config.issuer)
    .setSubject(clientId)
    .setAudience(resource)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttl)
    .setJti(randomUUID())
    .sign(ctx.key.privateKey);

  return { access_token: accessToken, token_type: "Bearer", expires_in: ttl, scope };
}

/** RFC 8707: exactly one resource, and one this server issues tokens for. */
function checkResource(resources: string[], allowed: string[]): string {
  const [resource, ...rest] = resources;
  if (!resource) throw invalidTarget("resource is required");
  if (rest.length > 0) throw invalidTarget("exactly one resource may be requested");
  if (!allowed.includes(resource)) throw invalidTarget("resource is not served by this authorization server");
  return resource;
}

/** Verifies the private_key_jwt assertion against the document's jwks and spends its jti. */
async function authenticate(assertion: string, client: ClientMetadata, ctx: TokenContext, nowMs: number) {
  let payload: JWTPayload;
  try {
    const keys = createLocalJWKSet(client.jwks);
    ({ payload } = await jwtVerify(assertion, keys, {
      algorithms: ["ES256"],
      issuer: client.client_id,
      subject: client.client_id,
      audience: tokenEndpoint(ctx.config.issuer),
      requiredClaims: ["exp", "jti"],
      clockTolerance: CLOCK_SKEW_S,
      currentDate: new Date(nowMs),
    }));
  } catch (err) {
    throw invalidClient(assertionFailure(err));
  }

  const nowS = Math.floor(nowMs / 1000);
  const exp = payload.exp as number;
  if (exp - nowS > MAX_ASSERTION_LIFETIME_S + CLOCK_SKEW_S) {
    throw invalidClient(`client assertion must expire within ${MAX_ASSERTION_LIFETIME_S} s`);
  }
  if (payload.iat !== undefined && exp - payload.iat > MAX_ASSERTION_LIFETIME_S) {
    throw invalidClient(`client assertion lifetime exceeds ${MAX_ASSERTION_LIFETIME_S} s`);
  }
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw invalidClient("client assertion jti must be a non-empty string");
  }
  if (!ctx.jtis.use(`${client.client_id}\n${payload.jti}`, exp + CLOCK_SKEW_S, nowS)) {
    throw invalidClient("client assertion jti was already used");
  }
}

function assertionFailure(err: unknown): string {
  if (err instanceof errors.JWTExpired) return "client assertion has expired";
  if (err instanceof errors.JWSSignatureVerificationFailed) return "client assertion signature is invalid";
  if (err instanceof errors.JWKSNoMatchingKey) return "no key in the client's jwks matches the assertion";
  if (err instanceof errors.JWTClaimValidationFailed) return `client assertion claim ${err.claim} is invalid`;
  if (err instanceof errors.JOSEAlgNotAllowed) return "client assertion must be signed with ES256";
  return "client assertion is invalid";
}

/**
 * Every requested scope must be both registered in the client's document and supported.
 * Without a `scope` parameter the client gets every supported scope its document lists.
 */
function grantScope(requested: string | null, registered: string): string {
  const supported = new Set<string>(SCOPES_SUPPORTED);
  const allowed = new Set(registered.split(" ").filter((s) => supported.has(s)));
  const wanted = requested === null || requested.trim() === "" ? [...allowed] : splitScope(requested);
  if (wanted.length === 0) throw invalidScope("no scope can be granted to this client");
  const refused = wanted.filter((s) => !allowed.has(s));
  if (refused.length > 0) throw invalidScope(`scope not allowed: ${refused.join(" ")}`);
  return wanted.join(" ");
}

function splitScope(scope: string): string[] {
  return [...new Set(scope.split(" ").filter((s) => s.length > 0))];
}
