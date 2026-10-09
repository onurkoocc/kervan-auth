import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { calculateJwkThumbprint, type JWK } from "jose";

/** The token signing key: ES256 on P-256, identified by its RFC 7638 thumbprint. */
export interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  publicJwk: JWK;
}

export async function signingKeyFrom(privateKey: KeyObject): Promise<SigningKey> {
  if (privateKey.asymmetricKeyType !== "ec" || privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("the signing key must be an EC P-256 private key");
  }
  const { kty, crv, x, y } = createPublicKey(privateKey).export({ format: "jwk" });
  const base = { kty, crv, x, y } as JWK;
  const kid = await calculateJwkThumbprint(base, "sha256");
  return { kid, privateKey, publicJwk: { ...base, kid, alg: "ES256", use: "sig" } };
}

/** Reads a PEM private key from `file`, or generates one kept in memory only (SPEC §2). */
export async function loadSigningKey(file: string | undefined): Promise<SigningKey> {
  const privateKey = file
    ? createPrivateKey(readFileSync(file, "utf8"))
    : generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  return signingKeyFrom(privateKey);
}
