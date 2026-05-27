/**
 * @hanzo/iam/validation — canonical identity-attribute validators.
 *
 * One source of truth for "is this a valid phone number / email / etc."
 * across every Hanzo product (web, mobile, server). The Go IAM server
 * normalizes phones to E.164 on store and looks them up by E.164 on
 * read; this module is the JS/TS counterpart so frontends produce the
 * exact form the server expects.
 *
 * Importing from @hanzo/iam/validation has zero runtime cost beyond
 * libphonenumber-js — no IAM client construction, no JWT verification,
 * no React. Safe for any environment (browser, Node, React Native).
 *
 * @example
 * ```ts
 * import { isValidPhone, isValidEmail } from "@hanzo/iam/validation"
 *
 * isValidPhone("6178888888", "+1")    // true  — boston US number
 * isValidPhone("6178888888", "")      // false — no country code
 * isValidPhone("5550110001", "+1")    // false — US 555-01XX reserved
 * isValidEmail("user@example.com")    // true
 * ```
 */
/**
 * Email format check — RFC 5322 in spirit, single-line regex in practice.
 *
 * The server validates against a more thorough RFC parser; this is a
 * cheap client-side gate to flip the Send Code button. False positives
 * (passes here, server rejects) fall back to a clear server error;
 * false negatives don't exist for any well-formed address.
 */
declare const isValidEmail: (email: string) => boolean;
/**
 * Strict E.164 phone validation.
 *
 * `nationalDigits` is the digits the user typed — no `+`, no country
 * code prefix. `countryCode` is the dialing prefix selected from the
 * country dropdown — `"+1"` for US/CA, `"+44"` for UK, etc. Either
 * `"1"` (no leading `+`) or `"+1"` (with) is accepted.
 *
 * Returns true only when libphonenumber-js's national-numbering-plan
 * tables say the resulting E.164 is a real, dial-able number in that
 * country. Reserved/fictional ranges (US 555-01XX, GB 7700-9XXXXX,
 * country-test pools) fail here even though they pass a naive length
 * check.
 *
 * Why strict matters: a permissive length-only check accepts inputs
 * like `6178888888` with no `+1` selected. Frontends then store the
 * raw national digits, the IAM server records them without a country
 * prefix, and a later login attempt (which always sends E.164
 * `+16178888888`) fails to match the stored row. The user appears to
 * be a different account and their data goes invisible. One canonical
 * validator on every input prevents the divergence.
 */
declare const isValidPhone: (nationalDigits: string, countryCode: string) => boolean;

export { isValidEmail, isValidPhone };
