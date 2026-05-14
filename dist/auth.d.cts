import { IamConfig, IamAuthResult } from './types.cjs';

/**
 * JWT validation using jose library + OIDC JWKS discovery.
 *
 * Validates access/ID tokens issued by Hanzo IAM.
 */

/** Clear cached JWKS key sets (useful for testing or key rotation). */
declare function clearJwksCache(): void;
/**
 * Validate a JWT access token against IAM's JWKS.
 *
 * Uses OIDC discovery to find the JWKS URI, then verifies the token
 * signature, issuer, audience, and expiry using the `jose` library.
 */
declare function validateToken(token: string, config: IamConfig): Promise<IamAuthResult>;

export { clearJwksCache, validateToken };
