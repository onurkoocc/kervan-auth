import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadSigningKey } from "../src/keys.js";

function pemFile(pem: string): string {
  const file = join(mkdtempSync(join(tmpdir(), "kervan-auth-key-")), "key.pem");
  writeFileSync(file, pem);
  return file;
}

describe("signing key", () => {
  it("loads a P-256 key from SIGNING_KEY_FILE with a stable kid", async () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const file = pemFile(privateKey.export({ format: "pem", type: "pkcs8" }) as string);
    const a = await loadSigningKey(file);
    const b = await loadSigningKey(file);
    expect(a.kid).toBe(b.kid);
    expect(a.publicJwk).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid: a.kid });
    expect(a.publicJwk).not.toHaveProperty("d");
  });

  it("generates a fresh key when no file is given", async () => {
    const a = await loadSigningKey(undefined);
    const b = await loadSigningKey(undefined);
    expect(a.kid).not.toBe(b.kid);
  });

  it("refuses a key that is not EC P-256", async () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const file = pemFile(privateKey.export({ format: "pem", type: "pkcs8" }) as string);
    await expect(loadSigningKey(file)).rejects.toThrow(/P-256/);
  });
});
