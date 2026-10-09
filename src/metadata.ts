import { SCOPES_SUPPORTED } from "./config.js";

/** RFC 8414 authorization server metadata, exactly the SPEC §3.1 shape. */
export function authorizationServerMetadata(issuer: string) {
  return {
    issuer,
    token_endpoint: tokenEndpoint(issuer),
    jwks_uri: `${issuer}/jwks.json`,
    grant_types_supported: ["client_credentials"],
    token_endpoint_auth_methods_supported: ["private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported: ["ES256"],
    scopes_supported: [...SCOPES_SUPPORTED],
    client_id_metadata_document_supported: true,
    resource_indicators_supported: true,
  };
}

export function tokenEndpoint(issuer: string): string {
  return `${issuer}/token`;
}
