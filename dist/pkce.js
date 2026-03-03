/**
 * PKCE (Proof Key for Code Exchange) utilities for browser-side OAuth2 flows.
 *
 * PKCE utilities for OAuth2 flows, using native Web Crypto API.
 */
function generateRandomString(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(36).padStart(2, "0"))
        .join("")
        .slice(0, length);
}
async function sha256(plain) {
    const encoder = new TextEncoder();
    return crypto.subtle.digest("SHA-256", encoder.encode(plain));
}
function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/** Generate a PKCE code verifier + challenge pair. */
export async function generatePkceChallenge() {
    const codeVerifier = generateRandomString(64);
    const hash = await sha256(codeVerifier);
    const codeChallenge = base64UrlEncode(hash);
    return { codeVerifier, codeChallenge };
}
/** Generate a random state parameter for CSRF protection. */
export function generateState() {
    return generateRandomString(32);
}
//# sourceMappingURL=pkce.js.map