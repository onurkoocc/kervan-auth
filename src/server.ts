import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { CimdResolver } from "./cimd.js";
import type { Config } from "./config.js";
import type { SigningKey } from "./keys.js";
import type { Fields, Logger } from "./log.js";
import { authorizationServerMetadata } from "./metadata.js";
import { OAuthError, invalidRequest } from "./oauth-error.js";
import { JtiCache } from "./replay.js";
import { issueToken, type TokenOutcome } from "./token.js";

const MAX_BODY_BYTES = 16 * 1024;

export interface AppOptions {
  config: Config;
  key: SigningKey;
  logger: Logger;
  /** Overrides for tests; defaults follow SPEC §3.2 (2 s timeout, 60 s cache). */
  cimdTimeoutMs?: number;
  cimdCacheTtlMs?: number;
  now?: () => number;
}

class BodyTooLarge extends Error {}

export function createApp(opts: AppOptions): Server {
  const { config, key, logger } = opts;
  const metadata = authorizationServerMetadata(config.issuer);
  const jwks = { keys: [key.publicJwk] };
  const cimd = new CimdResolver({
    allowedHosts: config.cimdAllowedHosts,
    ...(opts.cimdTimeoutMs !== undefined && { timeoutMs: opts.cimdTimeoutMs }),
    ...(opts.cimdCacheTtlMs !== undefined && { cacheTtlMs: opts.cimdCacheTtlMs }),
    ...(opts.now !== undefined && { now: opts.now }),
  });
  const tokenCtx = { config, key, cimd, jtis: new JtiCache(), ...(opts.now !== undefined && { now: opts.now }) };

  async function handleToken(req: IncomingMessage, res: ServerResponse, fields: Fields): Promise<void> {
    const outcome: TokenOutcome = {};
    const noStore = { "cache-control": "no-store", pragma: "no-cache" };
    try {
      const type = (req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
      if (type !== "application/x-www-form-urlencoded") {
        throw invalidRequest("Content-Type must be application/x-www-form-urlencoded");
      }
      const body = await readBody(req);
      const token = await issueToken(new URLSearchParams(body), tokenCtx, outcome);
      Object.assign(fields, outcome);
      sendJson(res, 200, token, noStore);
    } catch (err) {
      Object.assign(fields, outcome);
      if (err instanceof BodyTooLarge) {
        fields.error = "invalid_request";
        sendJson(res, 413, { error: "invalid_request", error_description: "request body is too large" }, { ...noStore, connection: "close" });
        return;
      }
      if (!(err instanceof OAuthError)) throw err;
      fields.error = err.error;
      fields.error_description = err.description;
      sendJson(res, err.status, err.body(), noStore);
    }
  }

  async function route(req: IncomingMessage, res: ServerResponse, fields: Fields): Promise<void> {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    fields.path = path;
    const get = req.method === "GET" || req.method === "HEAD";
    switch (path) {
      case "/health":
        if (!get) return methodNotAllowed(res, "GET");
        return sendJson(res, 200, { status: "ok" });
      case "/.well-known/oauth-authorization-server":
        if (!get) return methodNotAllowed(res, "GET");
        return sendJson(res, 200, metadata, { "cache-control": "max-age=300" });
      case "/jwks.json":
        if (!get) return methodNotAllowed(res, "GET");
        return sendJson(res, 200, jwks, { "cache-control": "max-age=300" });
      case "/token":
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        return handleToken(req, res, fields);
      default:
        return sendJson(res, 404, { error: "not_found" });
    }
  }

  return createServer((req, res) => {
    const started = performance.now();
    const fields: Fields = { trace_id: traceId(req), method: req.method };
    res.on("finish", () => {
      const status = res.statusCode;
      const token = fields.path === "/token" && req.method === "POST";
      const msg = !token ? "request" : status === 200 ? "token issued" : "token refused";
      const level = status >= 500 ? "error" : token && status >= 400 ? "warn" : "info";
      logger.log(level, msg, { ...fields, status, duration_ms: Math.round(performance.now() - started) });
    });
    route(req, res, fields).catch((err: unknown) => {
      logger.log("error", "unhandled error", {
        ...fields,
        reason: err instanceof Error ? err.message : String(err),
      });
      if (!res.headersSent) sendJson(res, 500, { error: "server_error" });
      else res.destroy();
    });
  });
}

/** The trace id of a W3C `traceparent` header, or a fresh one. */
function traceId(req: IncomingMessage): string {
  const header = req.headers.traceparent;
  const match = typeof header === "string" ? /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/.exec(header) : null;
  return match?.[1] ?? randomBytes(16).toString("hex");
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        req.pause();
        reject(new BodyTooLarge());
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    ...headers,
  });
  res.end(res.req.method === "HEAD" ? undefined : text);
}

function methodNotAllowed(res: ServerResponse, allow: string): void {
  sendJson(res, 405, { error: "method_not_allowed" }, { allow });
}
