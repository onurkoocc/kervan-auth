import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, ConfigError } from "../src/config.js";
import { startAuth, type AuthServer } from "./helpers.js";

const committed = JSON.parse(readFileSync(new URL("../docs/oauth-metadata.json", import.meta.url), "utf8"));

describe("authorization server metadata", () => {
  let auth: AuthServer;
  beforeAll(async () => {
    auth = await startAuth({ ISSUER: "http://auth:9000" });
  });
  afterAll(() => auth.close());

  it("serves exactly docs/oauth-metadata.json for ISSUER=http://auth:9000", async () => {
    const res = await fetch(`${auth.url}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    const served = (await res.json()) as Record<string, unknown>;
    expect(served).toStrictEqual(committed);
    expect(Object.keys(served)).toStrictEqual(Object.keys(committed));
  });

  it("builds the document from ISSUER", async () => {
    const other = await startAuth({ ISSUER: "https://auth.example.test/" });
    try {
      const doc = (await (await fetch(`${other.url}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
      expect(doc.issuer).toBe("https://auth.example.test");
      expect(doc.token_endpoint).toBe("https://auth.example.test/token");
      expect(doc.jwks_uri).toBe("https://auth.example.test/jwks.json");
    } finally {
      await other.close();
    }
  });

  it("publishes the public ES256 signing key with its kid", async () => {
    const jwks = (await (await fetch(`${auth.url}/jwks.json`)).json()) as { keys: Record<string, unknown>[] };
    expect(jwks.keys).toHaveLength(1);
    const [key] = jwks.keys;
    expect(key).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid: auth.key.kid });
    expect(key).not.toHaveProperty("d");
  });

  it("answers /health", async () => {
    const res = await fetch(`${auth.url}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toStrictEqual({ status: "ok" });
  });

  it("answers unknown paths with 404 and wrong methods with 405", async () => {
    expect((await fetch(`${auth.url}/nope`)).status).toBe(404);
    expect((await fetch(`${auth.url}/token`)).status).toBe(405);
    expect((await fetch(`${auth.url}/jwks.json`, { method: "POST" })).status).toBe(405);
  });
});

describe("configuration", () => {
  it("defaults to the compose values", () => {
    const c = loadConfig({});
    expect(c).toMatchObject({
      port: 9000,
      issuer: "http://auth:9000",
      allowedResources: ["http://mcp:3001/mcp"],
      cimdAllowedHosts: ["voice"],
      tokenTtlSeconds: 300,
    });
    expect(c.logFile).toBeUndefined();
  });

  it("splits comma-separated lists and refuses bad numbers", () => {
    expect(loadConfig({ ALLOWED_RESOURCES: " http://a/mcp , http://b/mcp ," }).allowedResources).toStrictEqual([
      "http://a/mcp",
      "http://b/mcp",
    ]);
    expect(() => loadConfig({ TOKEN_TTL_SECONDS: "0" })).toThrow(ConfigError);
    expect(() => loadConfig({ ISSUER: "auth:9000" })).toThrow(ConfigError);
  });
});
