import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalJWKSet, decodeProtectedHeader, generateKeyPair, jwtVerify, type JSONWebKeySet } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { fileSink } from "../src/log.js";
import {
  ISSUER,
  RESOURCE,
  makeAssertion,
  makeClient,
  metadataDocument,
  postToken,
  serveJson,
  startAuth,
  startCimdHost,
  tokenParams,
  type AuthServer,
  type CimdHost,
  type TestClient,
} from "./helpers.js";

const PATH = "/client-metadata.json";

let host: CimdHost;
let client: TestClient;
let auth: AuthServer;

beforeAll(async () => {
  host = await startCimdHost();
  client = await makeClient(`${host.origin}${PATH}`);
  host.route(PATH, serveJson(metadataDocument(client)));
});
afterAll(() => host.close());

beforeEach(async () => {
  host.hits.clear();
  auth = await startAuth({}, { cimdTimeoutMs: 300 });
});
afterEach(() => auth.close());

async function expectRefusal(params: URLSearchParams, status: number, error: string, description?: RegExp) {
  const res = await postToken(auth, params);
  expect(res.status).toBe(status);
  expect(res.body.error).toBe(error);
  expect(typeof res.body.error_description).toBe("string");
  if (description) expect(res.body.error_description).toMatch(description);
  expect(res.body).not.toHaveProperty("access_token");
  return res;
}

describe("token issuance", () => {
  it("issues an ES256 access token for a CIMD client", async () => {
    const res = await postToken(auth, await tokenParams(client));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.body).toMatchObject({ token_type: "Bearer", expires_in: 300, scope: "shipments:read tickets:write" });
    expect(host.hits.get(PATH)).toBe(1);

    const token = res.body.access_token as string;
    const header = decodeProtectedHeader(token);
    expect(header).toMatchObject({ alg: "ES256", kid: auth.key.kid });

    const jwks = (await (await fetch(`${auth.url}/jwks.json`)).json()) as JSONWebKeySet;
    const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), {
      issuer: ISSUER,
      audience: RESOURCE,
      algorithms: ["ES256"],
    });
    expect(payload.iss).toBe(ISSUER);
    expect(payload.sub).toBe(client.clientId);
    expect(payload.client_id).toBe(client.clientId);
    expect(payload.aud).toBe(RESOURCE);
    expect(typeof payload.aud).toBe("string");
    expect(payload.scope).toBe("shipments:read tickets:write");
    expect(payload.exp! - payload.iat!).toBe(300);
    expect(Math.abs(payload.iat! - Date.now() / 1000)).toBeLessThan(5);
    expect(typeof payload.jti).toBe("string");
  });

  it("uses TOKEN_TTL_SECONDS", async () => {
    await auth.close();
    auth = await startAuth({ TOKEN_TTL_SECONDS: "120" });
    const res = await postToken(auth, await tokenParams(client));
    expect(res.body.expires_in).toBe(120);
    const { payload } = await jwtVerify(res.body.access_token as string, createLocalJWKSet({ keys: [auth.key.publicJwk] }));
    expect(payload.exp! - payload.iat!).toBe(120);
  });

  it("grants the document's scopes when no scope is requested", async () => {
    const res = await postToken(auth, await tokenParams(client, { scope: null }));
    expect(res.status).toBe(200);
    expect(res.body.scope).toBe("shipments:read deliveries:write tickets:write help:read");
  });

  it("caches the client metadata document", async () => {
    expect((await postToken(auth, await tokenParams(client))).status).toBe(200);
    expect((await postToken(auth, await tokenParams(client))).status).toBe(200);
    expect(host.hits.get(PATH)).toBe(1);
  });

  it("fetches the document again after 60 s", async () => {
    await auth.close();
    let now = Date.now();
    auth = await startAuth({}, { now: () => now });
    expect((await postToken(auth, await tokenParams(client))).status).toBe(200);
    now += 61_000;
    // Assertions are checked against the server clock, so sign one valid at that time.
    const assertion = await makeAssertion(client, { iat: 61, exp: 61 + 60 });
    expect((await postToken(auth, await tokenParams(client, { client_assertion: assertion }))).status).toBe(200);
    expect(host.hits.get(PATH)).toBe(2);
  });

  it("logs JSON lines without assertions or tokens", async () => {
    await auth.close();
    const file = join(mkdtempSync(join(tmpdir(), "kervan-auth-")), "logs", "auth.jsonl");
    auth = await startAuth({}, { sinks: [fileSink(file)] });
    const params = await tokenParams(client);
    const res = await postToken(auth, params);
    await postToken(auth, await tokenParams(client, { resource: "http://elsewhere/mcp" }));

    const fileLines = readFileSync(file, "utf8").trim().split("\n");
    expect(fileLines).toStrictEqual(auth.lines);
    const entries = auth.lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const e of entries) {
      expect(e).toMatchObject({ service: "auth" });
      expect(typeof e.ts).toBe("string");
      expect(["info", "warn", "error"]).toContain(e.level);
      expect(typeof e.msg).toBe("string");
    }
    expect(entries.find((e) => e.msg === "token issued")).toMatchObject({
      level: "info",
      status: 200,
      client_id: client.clientId,
      scope: "shipments:read tickets:write",
      resource: RESOURCE,
    });
    expect(entries.find((e) => e.msg === "token refused")).toMatchObject({ level: "warn", status: 400, error: "invalid_target" });
    const all = auth.lines.join("\n");
    expect(all).not.toContain(params.get("client_assertion"));
    expect(all).not.toContain(res.body.access_token as string);
  });
});

describe("token refusals", () => {
  it("refuses a client_id on a host outside CIMD_ALLOWED_HOSTS without fetching it", async () => {
    const outsider = await makeClient(client.clientId.replace("127.0.0.1", "localhost"));
    await expectRefusal(await tokenParams(outsider), 401, "invalid_client", /host is not allowed/);
    expect(host.hits.size).toBe(0);
  });

  it("refuses a document whose client_id differs from its URL", async () => {
    const path = "/mismatch.json";
    const impostor = await makeClient(`${host.origin}${path}`);
    host.route(path, serveJson(metadataDocument(impostor, { client_id: client.clientId })));
    await expectRefusal(await tokenParams(impostor), 401, "invalid_client", /differs/);
  });

  it("refuses an assertion with a bad signature", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    const forged = await makeAssertion(client, { key: privateKey });
    await expectRefusal(await tokenParams(client, { client_assertion: forged }), 401, "invalid_client", /signature/);
  });

  it("refuses an assertion signed by a key the document does not list", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    const forged = await makeAssertion(client, { key: privateKey, kid: "unknown-kid" });
    await expectRefusal(await tokenParams(client, { client_assertion: forged }), 401, "invalid_client", /no key/);
  });

  it("accepts a jti once", async () => {
    const assertion = await makeAssertion(client);
    expect((await postToken(auth, await tokenParams(client, { client_assertion: assertion }))).status).toBe(200);
    await expectRefusal(await tokenParams(client, { client_assertion: assertion }), 401, "invalid_client", /already used/);
  });

  it("refuses an expired assertion", async () => {
    const expired = await makeAssertion(client, { iat: -120, exp: -60 });
    await expectRefusal(await tokenParams(client, { client_assertion: expired }), 401, "invalid_client", /expired/);
  });

  it("refuses an assertion that lives longer than 60 s", async () => {
    const long = await makeAssertion(client, { exp: 600 });
    await expectRefusal(await tokenParams(client, { client_assertion: long }), 401, "invalid_client", /60 s/);
  });

  it("refuses an assertion for another audience or issuer", async () => {
    const wrongAud = await makeAssertion(client, { aud: "http://other:9000/token" });
    await expectRefusal(await tokenParams(client, { client_assertion: wrongAud }), 401, "invalid_client", /aud/);
    const wrongIss = await makeAssertion(client, { iss: "http://someone-else/" });
    await expectRefusal(await tokenParams(client, { client_assertion: wrongIss }), 401, "invalid_client", /iss/);
  });

  it("refuses a scope the document does not register", async () => {
    const path = "/narrow.json";
    const narrow = await makeClient(`${host.origin}${path}`);
    host.route(path, serveJson(metadataDocument(narrow, { scope: "shipments:read" })));
    await expectRefusal(await tokenParams(narrow, { scope: "shipments:read tickets:write" }), 400, "invalid_scope", /tickets:write/);
  });

  it("refuses a scope the server does not support", async () => {
    const path = "/greedy.json";
    const greedy = await makeClient(`${host.origin}${path}`);
    host.route(path, serveJson(metadataDocument(greedy, { scope: "shipments:read admin" })));
    await expectRefusal(await tokenParams(greedy, { scope: "shipments:read admin" }), 400, "invalid_scope", /admin/);
  });

  it("refuses a request without resource", async () => {
    await expectRefusal(await tokenParams(client, { resource: null }), 400, "invalid_target", /required/);
  });

  it("refuses a resource outside ALLOWED_RESOURCES", async () => {
    await expectRefusal(await tokenParams(client, { resource: "http://mcp:3001/mcp/" }), 400, "invalid_target");
    await expectRefusal(await tokenParams(client, { resource: "http://evil:3001/mcp" }), 400, "invalid_target");
  });

  it("refuses more than one resource, since aud is a single string", async () => {
    await expectRefusal(await tokenParams(client, { resource: [RESOURCE, RESOURCE] }), 400, "invalid_target", /exactly one/);
  });

  it("refuses other grant types and malformed requests", async () => {
    await expectRefusal(await tokenParams(client, { grant_type: "authorization_code" }), 400, "unsupported_grant_type");
    await expectRefusal(await tokenParams(client, { grant_type: null }), 400, "invalid_request");
    await expectRefusal(await tokenParams(client, { client_id: null }), 400, "invalid_request");
    await expectRefusal(await tokenParams(client, { scope: ["help:read", "help:read"] }), 400, "invalid_request", /repeated/);
    await expectRefusal(await tokenParams(client, { client_assertion: null }), 401, "invalid_client");
    await expectRefusal(await tokenParams(client, { client_assertion_type: "urn:other" }), 401, "invalid_client");
  });

  it("refuses a body that is not form-encoded", async () => {
    const res = await postToken(auth, await tokenParams(client), "application/json");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
  });

  it("refuses a client whose document cannot be fetched in time", async () => {
    const path = "/slow.json";
    const slow = await makeClient(`${host.origin}${path}`);
    host.route(path, (_req, res) => {
      setTimeout(() => serveJson(metadataDocument(slow))(_req, res), 1500).unref();
    });
    await expectRefusal(await tokenParams(slow), 401, "invalid_client", /timed out/);
  });

  it("refuses a client whose document is missing or not JSON", async () => {
    await expectRefusal(await tokenParams(await makeClient(`${host.origin}/absent.json`)), 401, "invalid_client", /HTTP 404/);
    host.route("/garbage.json", (_req, res) => res.writeHead(200).end("not json"));
    await expectRefusal(await tokenParams(await makeClient(`${host.origin}/garbage.json`)), 401, "invalid_client", /not JSON/);
  });

  it("does not follow redirects when fetching a document", async () => {
    host.route("/redirect.json", (_req, res) => res.writeHead(302, { location: PATH }).end());
    const redirected = await makeClient(`${host.origin}/redirect.json`);
    await expectRefusal(await tokenParams(redirected), 401, "invalid_client");
    expect(host.hits.get(PATH)).toBeUndefined();
  });

  it("refuses a document that registers another grant type", async () => {
    const path = "/codeflow.json";
    const c = await makeClient(`${host.origin}${path}`);
    host.route(path, serveJson(metadataDocument(c, { grant_types: ["authorization_code"] })));
    await expectRefusal(await tokenParams(c), 400, "unauthorized_client");
  });
});
