/**
 * JWT validation using jose library + OIDC JWKS discovery.
 *
 * Validates access/ID tokens issued by Hanzo IAM.
 */
import type { IamConfig, IamAuthResult } from "./types.js";
/** Clear cached JWKS key sets (useful for testing or key rotation). */
export declare function clearJwksCache(): void;
/**
 * Validate a JWT access token against IAM's JWKS.
 *
 * Uses OIDC discovery to find the JWKS URI, then verifies the token
 * signature, issuer, audience, and expiry using the `jose` library.
 */
export declare function validateToken(token: string, config: IamConfig): Promise<IamAuthResult>;
//# sourceMappingURL=auth.d.ts.map