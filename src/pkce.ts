/**
 * PKCE (Proof Key for Code Exchange, RFC 7636) utilities for OAuth2/OIDC.
 *
 * Uses the native Web Crypto API (`crypto.getRandomValues`,
 * `crypto.subtle.digest`) — available in modern browsers and Node ≥ 18.
 *
 * The code verifier is the base64url encoding of 32 cryptographically
 * random bytes (256 bits of entropy), which yields a 43-character
 * `[A-Za-z0-9-_]` string — within RFC 7636's 43–128 character range and
 * well above the minimum recommended entropy. The challenge is the
 * base64url-encoded SHA-256 of the verifier (the `S256` method).
 */

/** Number of random bytes for the verifier and state — 256 bits each. */
const ENTROPY_BYTES = 32;

function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes.buffer);
}

async function sha256(plain: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  return crypto.subtle.digest("SHA-256", encoder.encode(plain));
}

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Generate a PKCE code verifier + S256 challenge pair.
 *
 * `codeVerifier` carries 256 bits of entropy; `codeChallenge` is its
 * base64url-encoded SHA-256 digest. Send `code_challenge` +
 * `code_challenge_method=S256` on the authorize request, and
 * `code_verifier` on the token exchange.
 */
export async function generatePKCEChallenge(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
}> {
  const codeVerifier = randomBase64Url(ENTROPY_BYTES);
  const hash = await sha256(codeVerifier);
  const codeChallenge = base64UrlEncode(hash);
  return { codeVerifier, codeChallenge };
}

/** Generate a high-entropy (256-bit) `state` parameter for CSRF protection. */
export function generateState(): string {
  return randomBase64Url(ENTROPY_BYTES);
}
