/** Configuration from the environment only (SPEC §2). Defaults are the compose values. */
export interface Config {
  port: number;
  /** Without a trailing slash; endpoint URLs are built from it. */
  issuer: string;
  allowedResources: string[];
  /** Hosts client metadata documents may be fetched from, as `host` or `host:port`. */
  cimdAllowedHosts: string[];
  tokenTtlSeconds: number;
  logFile: string | undefined;
  signingKeyFile: string | undefined;
}

export const SCOPES_SUPPORTED = [
  "shipments:read",
  "deliveries:write",
  "tickets:write",
  "help:read",
] as const;

export class ConfigError extends Error {}

function list(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function positiveInt(name: string, value: string): number {
  if (!/^[1-9][0-9]*$/.test(value)) throw new ConfigError(`${name} must be a positive integer`);
  return Number(value);
}

function absoluteHttpUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${name} must be an absolute URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ConfigError(`${name} must be an http(s) URL`);
  }
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const issuer = absoluteHttpUrl("ISSUER", env.ISSUER ?? "http://auth:9000").replace(/\/+$/, "");
  const allowedResources = list(env.ALLOWED_RESOURCES ?? "http://mcp:3001/mcp");
  for (const r of allowedResources) absoluteHttpUrl("ALLOWED_RESOURCES", r);
  const port = env.PORT ? positiveInt("PORT", env.PORT) : 9000;
  if (port > 65535) throw new ConfigError("PORT must be at most 65535");
  return {
    port,
    issuer,
    allowedResources,
    cimdAllowedHosts: list(env.CIMD_ALLOWED_HOSTS ?? "voice").map((h) => h.toLowerCase()),
    tokenTtlSeconds: positiveInt("TOKEN_TTL_SECONDS", env.TOKEN_TTL_SECONDS ?? "300"),
    logFile: env.LOG_FILE || undefined,
    signingKeyFile: env.SIGNING_KEY_FILE || undefined,
  };
}
