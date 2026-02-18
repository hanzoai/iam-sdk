/**
 * @hanzo/iam/billing — REMOVED
 *
 * Billing has moved to @hanzo/commerce (or commerce.js).
 *
 * ```ts
 * // Use this instead:
 * import { Commerce } from '@hanzo/commerce'
 * const commerce = new Commerce({ commerceUrl: '...' })
 * await commerce.getBalance(userId)
 * ```
 *
 * @deprecated This module is no longer functional. Use @hanzo/commerce.
 */

throw new Error(
  '@hanzo/iam/billing has been removed. Use @hanzo/commerce or commerce.js instead. ' +
  'See: https://docs.hanzo.ai/services/commerce/sdk'
)
