/** An RFC 6749 §5.2 error answer: `{"error", "error_description"}` with status 400 or 401. */
export class OAuthError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status: 400 | 401 = 400,
  ) {
    super(`${error}: ${description}`);
  }

  body(): { error: string; error_description: string } {
    return { error: this.error, error_description: this.description };
  }
}

export const invalidRequest = (d: string) => new OAuthError("invalid_request", d);
export const invalidClient = (d: string) => new OAuthError("invalid_client", d, 401);
export const invalidScope = (d: string) => new OAuthError("invalid_scope", d);
export const invalidTarget = (d: string) => new OAuthError("invalid_target", d);
export const unauthorizedClient = (d: string) => new OAuthError("unauthorized_client", d);
export const unsupportedGrantType = (d: string) => new OAuthError("unsupported_grant_type", d);
