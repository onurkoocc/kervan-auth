import type { JSONWebKeySet } from "jose";
import { OAuthError, invalidClient, unauthorizedClient } from "./oauth-error.js";

/** The fields of a client ID metadata document (SPEC §3.2) this server relies on. */
export interface ClientMetadata {
  client_id: string;
  jwks: JSONWebKeySet;
  /** Space-separated scopes the client may ask for; absent means none. */
  scope: string;
}

export interface CimdOptions {
  allowedHosts: string[];
  timeoutMs?: number;
  cacheTtlMs?: number;
  maxBytes?: number;
  now?: () => number;
}

interface CacheEntry {
  expiresAt: number;
  doc: Promise<ClientMetadata>;
}

/**
 * Resolves CIMD client ids. Documents are fetched only from allow-listed hosts,
 * without following redirects, within a timeout, and cached on success.
 */
export class CimdResolver {
  private readonly allowedHosts: string[];
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly maxBytes: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(opts: CimdOptions) {
    this.allowedHosts = opts.allowedHosts.map((h) => h.toLowerCase());
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.cacheTtlMs = opts.cacheTtlMs ?? 60_000;
    this.maxBytes = opts.maxBytes ?? 64 * 1024;
    this.now = opts.now ?? Date.now;
  }

  async resolve(clientId: string): Promise<ClientMetadata> {
    const url = this.checkClientId(clientId);
    const now = this.now();
    const cached = this.cache.get(clientId);
    if (cached && cached.expiresAt > now) return cached.doc;

    const doc = this.fetchDocument(url, clientId);
    this.cache.set(clientId, { expiresAt: now + this.cacheTtlMs, doc });
    doc.catch(() => {
      if (this.cache.get(clientId)?.doc === doc) this.cache.delete(clientId);
    });
    return doc;
  }

  private checkClientId(clientId: string): URL {
    let url: URL;
    try {
      url = new URL(clientId);
    } catch {
      throw invalidClient("client_id must be the URL of a client metadata document");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw invalidClient("client_id must be an http(s) URL");
    }
    if (url.username || url.password || url.hash) {
      throw invalidClient("client_id must not carry credentials or a fragment");
    }
    if (!this.hostAllowed(url)) {
      throw invalidClient("client_id host is not allowed");
    }
    return url;
  }

  /** An entry `host:port` matches host and port; a bare `host` matches any port. */
  private hostAllowed(url: URL): boolean {
    const host = url.host.toLowerCase();
    const hostname = url.hostname.toLowerCase();
    return this.allowedHosts.some((entry) => (entry.includes(":") ? entry === host : entry === hostname));
  }

  private async fetchDocument(url: URL, clientId: string): Promise<ClientMetadata> {
    let text: string;
    try {
      const res = await fetch(url, {
        redirect: "error",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (res.status !== 200) {
        throw invalidClient(`client metadata document answered HTTP ${res.status}`);
      }
      if (Number(res.headers.get("content-length") ?? 0) > this.maxBytes) {
        throw invalidClient("client metadata document is too large");
      }
      text = await res.text();
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
        throw invalidClient("client metadata document fetch timed out");
      }
      throw invalidClient("client metadata document could not be fetched");
    }
    if (Buffer.byteLength(text) > this.maxBytes) {
      throw invalidClient("client metadata document is too large");
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      throw invalidClient("client metadata document is not JSON");
    }
    return validateDocument(raw, clientId);
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function validateDocument(raw: unknown, clientId: string): ClientMetadata {
  if (!isObject(raw)) throw invalidClient("client metadata document is not a JSON object");
  if (raw.client_id !== clientId) {
    throw invalidClient("client_id in the metadata document differs from the URL it was fetched from");
  }
  const method = raw.token_endpoint_auth_method;
  if (method !== undefined && method !== "private_key_jwt") {
    throw invalidClient("client must authenticate with private_key_jwt");
  }
  const grants = raw.grant_types;
  if (grants !== undefined && !(Array.isArray(grants) && grants.includes("client_credentials"))) {
    throw unauthorizedClient("client is not registered for client_credentials");
  }
  const jwks = raw.jwks;
  if (!isObject(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length === 0 || !jwks.keys.every(isObject)) {
    throw invalidClient("client metadata document has no jwks");
  }
  if (jwks.keys.some((k) => "d" in k)) {
    throw invalidClient("client metadata document jwks must hold public keys only");
  }
  const scope = raw.scope;
  if (scope !== undefined && typeof scope !== "string") {
    throw invalidClient("client metadata document scope must be a string");
  }
  return { client_id: clientId, jwks: jwks as unknown as JSONWebKeySet, scope: scope ?? "" };
}
