/**
 * Composable IAM views.
 *
 * Drop-in React components that mirror the server-rendered embedded
 * login + onboarding flows. Each component is independently usable —
 * you can render the whole `<Login>`, or just the `<WalletButton>`,
 * or just the `<EmailPasswordForm>`, or assemble a custom flow from
 * the step primitives.
 *
 * Discovery
 * =========
 *
 * `<Login>` reads `/v1/iam/auth/methods` from the configured IAM and
 * renders only the buttons whose backends are actually wired. There
 * is one source of truth — the server emits the method list, the
 * client renders exactly that. No env mismatch, no client-side
 * guessing.
 *
 * Composition example
 * ===================
 *
 * ```tsx
 * import { Login, OnboardingFlow } from '@hanzo/iam/views'
 *
 * function MyApp() {
 *   return location.pathname === '/onboarding'
 *     ? <OnboardingFlow serverUrl="/v1/iam" onComplete={(user) => ...} />
 *     : <Login serverUrl="/v1/iam" clientId="my-app" redirectUri={`${origin}/_/callback`} />
 * }
 * ```
 *
 * Or pull individual primitives for a custom layout:
 *
 * ```tsx
 * import { WalletButton, SocialButton, EmailPasswordForm, OTPStep } from '@hanzo/iam/views'
 *
 * function CustomLogin(props) {
 *   const { methods } = useAuthMethods(props.serverUrl)
 *   return (
 *     <>
 *       {methods.has('wallet') && <WalletButton {...props} />}
 *       {methods.providers().map(p => <SocialButton key={p} provider={p} {...props} />)}
 *       {methods.has('email_otp') && <OTPStep channel="email" {...props} />}
 *       <EmailPasswordForm {...props} />
 *     </>
 *   )
 * }
 * ```
 *
 * Onboarding decomposition
 * ========================
 *
 * The onboarding flow is the 5-step pipeline that mirrors the
 * `~/work/liquidity/id` shape:
 *
 *   <IdentityStep>   - PII (DOB, address)
 *   <DocumentsStep>  - multipart upload
 *   <BiometricStep>  - IDV provider handoff (/Persona/Jumio/custom)
 *   <ScreenStep>     - AML/sanctions
 *   <SubmitStep>     - finalize + fan-out
 *
 * Compose them yourself or use `<OnboardingFlow>` to get the full
 * pipeline with default styling + routing.
 *
 * @packageDocumentation
 */

// ============================================================
// types
// ============================================================

export type AuthMethodKind = 'password' | 'social' | 'wallet' | 'email_otp' | 'sms_otp'

export interface AuthMethod {
  kind: AuthMethodKind
  /** Set when kind = 'social'; one of 'google' | 'github' | 'apple' | … */
  provider?: string
  label: string
  is_primary: boolean
  is_secondary: boolean
}

export interface MethodsResponse {
  methods: AuthMethod[]
  require_2fa: boolean
}

/** Common props every view accepts. The redirectUri and state pair up
 * with the OIDC PKCE flow — see `@hanzo/iam/browser`. */
export interface FlowProps {
  /** Base URL of the IAM server, e.g. '/v1/iam' or 'https://hanzo.id'. */
  serverUrl: string
  clientId: string
  redirectUri: string
  /** The OIDC `state` param. Generate one per signinRedirect() call. */
  state: string
}

// ============================================================
// hooks
// ============================================================

/** Hook: fetches the live list of enabled auth methods. SSR-safe (no
 * fetch in node). */
export interface MethodsView {
  loading: boolean
  error: Error | null
  has: (kind: AuthMethodKind) => boolean
  providers: () => string[]
  raw: AuthMethod[]
  require2FA: boolean
}

export interface UseAuthMethodsOpts {
  serverUrl: string
  fetcher?: typeof fetch
}

// Implementation lives in `./views/use-auth-methods.tsx` when this
// subpath is built into the dist. The TS contract here is the public
// shape consumers depend on.
export declare function useAuthMethods(opts: UseAuthMethodsOpts): MethodsView

// ============================================================
// view components
// ============================================================

import type { ComponentType, ReactNode } from 'react'

export interface LoginProps extends FlowProps {
  /** Override individual button labels for white-label deployments. */
  labels?: Partial<{
    wallet: string
    googleSocial: string
    githubSocial: string
    appleSocial: string
    emailOtp: string
    smsOtp: string
    password: string
    divider: string
  }>
  /** Render-prop slot for the brand mark above the form. */
  brand?: ReactNode
  /** Optional class hook for the outer card; default styling is
   * monochrome to match the server-rendered template. */
  className?: string
  /** Called after successful sign-in (post-callback). When absent,
   * the redirect-uri flow takes the user back to your app's callback
   * route as configured by `redirectUri`. */
  onSuccess?: (token: string) => void
}

export interface SocialButtonProps extends FlowProps {
  /** 'google' | 'github' | 'apple' (or a custom provider key). */
  provider: string
  label?: string
}

export interface WalletButtonProps extends FlowProps {
  label?: string
}

export interface EmailPasswordFormProps extends FlowProps {
  initialEmail?: string
  onError?: (error: Error) => void
}

export interface OTPStepProps extends FlowProps {
  channel: 'email' | 'sms'
  /** Destination contact — when omitted the component prompts. */
  destination?: string
  label?: string
}

// Component declarations — implementations bundled by tsup from
// `./views/*.tsx`. The exported type ensures the public shape stays
// stable even as the impl evolves.
export declare const Login: ComponentType<LoginProps>
export declare const SocialButton: ComponentType<SocialButtonProps>
export declare const WalletButton: ComponentType<WalletButtonProps>
export declare const EmailPasswordForm: ComponentType<EmailPasswordFormProps>
export declare const OTPStep: ComponentType<OTPStepProps>

// ============================================================
// onboarding views
// ============================================================

/** Step ordering matches the embedded IAM /v1/iam/onboarding/* state
 * machine. Skip steps the operator's flow doesn't need. */
export type OnboardingStep =
  | 'identity'
  | 'documents'
  | 'biometric'
  | 'screen'
  | 'submit'

export interface OnboardingFlowProps {
  serverUrl: string
  /** Auth bearer token from the prior sign-in. Required to call
   * /v1/iam/onboarding endpoints. */
  token: string
  /** Subset of steps to render. Defaults to all five in canonical order. */
  steps?: OnboardingStep[]
  /** Fired when the user finishes the final step. */
  onComplete?: (applicationId: string) => void
  /** Brand-mark slot, same shape as Login. */
  brand?: ReactNode
  className?: string
}

export interface StepProps {
  serverUrl: string
  token: string
  applicationId?: string
  onNext: (applicationId: string) => void
  onError?: (error: Error) => void
}

export declare const OnboardingFlow: ComponentType<OnboardingFlowProps>
export declare const IdentityStep: ComponentType<StepProps>
export declare const DocumentsStep: ComponentType<StepProps>
export declare const BiometricStep: ComponentType<StepProps>
export declare const ScreenStep: ComponentType<StepProps>
export declare const SubmitStep: ComponentType<StepProps>
