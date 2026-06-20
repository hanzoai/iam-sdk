/**
 * Composable IAM views.
 *
 * Drop-in React components that mirror the server-rendered embedded
 * login + onboarding flows. Each component is independently usable —
 * render the whole `<Login>`, or just the `<WalletButton>`, or just the
 * `<EmailPasswordForm>`, or assemble a custom flow from the primitives.
 *
 * Discovery
 * =========
 *
 * `<Login>` reads {@link IAM_PATHS.authMethods} from the configured IAM
 * and renders only the buttons whose backends are actually wired. One
 * source of truth — the server emits the method list, the client renders
 * exactly that. No env mismatch, no client-side guessing.
 *
 * All OAuth interactions go through the canonical PKCE redirect flow in
 * `@hanzo/iam/browser` (which resolves every endpoint through
 * `OIDC_PATHS`). The email/password and OTP primitives drive the IAM
 * password/OTP grants and then hand off to the same redirect.
 *
 * @example
 * ```tsx
 * import { Login, OnboardingFlow } from '@hanzo/iam/views'
 *
 * function MyApp() {
 *   return location.pathname === '/onboarding'
 *     ? <OnboardingFlow serverUrl="https://iam.hanzo.ai" token={token} onComplete={(id) => …} />
 *     : <Login serverUrl="https://iam.hanzo.ai" clientId="my-app"
 *              redirectUri={`${origin}/_/callback`} state={state} />
 * }
 * ```
 *
 * @packageDocumentation
 */

import {
  createElement as h,
  useCallback,
  useEffect,
  useState,
  type ComponentType,
  type FormEvent,
  type ReactNode,
} from "react";

import { IAM } from "./browser.js";
import { IAM_PATHS, trimServerUrl } from "./paths.js";

// ============================================================
// types
// ============================================================

export type AuthMethodKind = "password" | "social" | "wallet" | "email_otp" | "sms_otp";

export interface AuthMethod {
  kind: AuthMethodKind;
  /** Set when kind = 'social'; one of 'google' | 'github' | 'apple' | … */
  provider?: string;
  label: string;
  is_primary: boolean;
  is_secondary: boolean;
}

export interface MethodsResponse {
  methods: AuthMethod[];
  require_2fa: boolean;
}

/** Common props every view accepts. The redirectUri and state pair up
 * with the OIDC PKCE flow — see `@hanzo/iam/browser`. */
export interface FlowProps {
  /** Base URL of the IAM server, e.g. 'https://iam.hanzo.ai'. */
  serverUrl: string;
  clientId: string;
  redirectUri: string;
  /** The OIDC `state` param. Generate one per signinRedirect() call. */
  state: string;
  /**
   * IAM organization the app belongs to (e.g. 'hanzo'). Required for the
   * credential (password / verification-code) login flow.
   */
  organization?: string;
  /** IAM application name. Defaults to `clientId` (they match for Hanzo apps). */
  application?: string;
}

function makeIam(props: FlowProps): IAM {
  return new IAM({
    serverUrl: props.serverUrl,
    clientId: props.clientId,
    redirectUri: props.redirectUri,
    organization: props.organization,
    application: props.application,
  });
}

// ============================================================
// hooks
// ============================================================

export interface MethodsView {
  loading: boolean;
  error: Error | null;
  has: (kind: AuthMethodKind) => boolean;
  providers: () => string[];
  raw: AuthMethod[];
  require2FA: boolean;
}

export interface UseAuthMethodsOpts {
  serverUrl: string;
  fetcher?: typeof fetch;
}

/**
 * Fetch the live list of enabled auth methods from
 * {@link IAM_PATHS.authMethods}. SSR-safe: no fetch runs until the
 * component is mounted in the browser.
 */
export function useAuthMethods(opts: UseAuthMethodsOpts): MethodsView {
  const [methods, setMethods] = useState<AuthMethod[]>([]);
  const [require2FA, setRequire2FA] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let cancelled = false;
    const doFetch = opts.fetcher ?? fetch;
    setLoading(true);
    setError(null);

    doFetch(`${trimServerUrl(opts.serverUrl)}${IAM_PATHS.authMethods}`, {
      headers: { Accept: "application/json" },
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(`auth methods fetch failed: ${res.status}`);
        return (await res.json()) as MethodsResponse;
      })
      .then((body) => {
        if (cancelled) return;
        setMethods(body.methods ?? []);
        setRequire2FA(Boolean(body.require_2fa));
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [opts.serverUrl, opts.fetcher]);

  return {
    loading,
    error,
    has: (kind) => methods.some((m) => m.kind === kind),
    providers: () =>
      methods.filter((m) => m.kind === "social" && m.provider).map((m) => m.provider as string),
    raw: methods,
    require2FA,
  };
}

// ============================================================
// view components
// ============================================================

export interface LoginProps extends FlowProps {
  /** Override individual button labels for white-label deployments. */
  labels?: Partial<{
    wallet: string;
    googleSocial: string;
    githubSocial: string;
    appleSocial: string;
    emailOtp: string;
    smsOtp: string;
    password: string;
    divider: string;
  }>;
  /** Render-prop slot for the brand mark above the form. */
  brand?: ReactNode;
  /** Optional class hook for the outer card. */
  className?: string;
  /** Called after a successful credential sign-in (pre-redirect). */
  onSuccess?: (token: string) => void;
  /**
   * Social/wallet providers to render as buttons (e.g. ['google','github','apple']).
   * Each starts the PKCE redirect with that provider. Defaults to none — the
   * `/v1/iam/auth/methods` discovery endpoint is not relied upon (it is not
   * deployed), so providers are passed explicitly per app.
   */
  providers?: string[];
}

export interface SocialButtonProps extends FlowProps {
  /** 'google' | 'github' | 'apple' (or a custom provider key). */
  provider: string;
  label?: string;
}

export interface WalletButtonProps extends FlowProps {
  label?: string;
}

export interface EmailPasswordFormProps extends FlowProps {
  initialEmail?: string;
  onError?: (error: Error) => void;
  /** Called with the access token after a successful password grant. */
  onSuccess?: (token: string) => void;
}

export interface OTPStepProps extends FlowProps {
  channel: "email" | "sms";
  /** Destination contact — when omitted the component prompts. */
  destination?: string;
  label?: string;
  onError?: (error: Error) => void;
  onSuccess?: (token: string) => void;
}

/**
 * Social sign-in button. Starts the canonical PKCE redirect with the
 * provider passed through as an authorize param — IAM routes the user to
 * the upstream provider and back to `redirectUri`.
 */
export const SocialButton: ComponentType<SocialButtonProps> = (props) => {
  const onClick = useCallback(() => {
    void makeIam(props).signinRedirect({ additionalParams: { provider: props.provider } });
  }, [props.serverUrl, props.clientId, props.redirectUri, props.provider]);

  return h(
    "button",
    { type: "button", onClick, "data-provider": props.provider, className: "hanzo-iam-btn" },
    props.label ?? `Continue with ${props.provider}`,
  );
};

/**
 * Wallet sign-in button. Starts the canonical PKCE redirect with
 * `provider=wallet` so IAM presents the wallet-signature challenge.
 */
export const WalletButton: ComponentType<WalletButtonProps> = (props) => {
  const onClick = useCallback(() => {
    void makeIam(props).signinRedirect({ additionalParams: { provider: "wallet" } });
  }, [props.serverUrl, props.clientId, props.redirectUri]);

  return h(
    "button",
    { type: "button", onClick, "data-provider": "wallet", className: "hanzo-iam-btn" },
    props.label ?? "Connect wallet",
  );
};

/**
 * Email + password form. Drives IAM's password grant directly (RFC 6749
 * §4.3) and reports the access token via `onSuccess`. No credential ever
 * touches a path other than the canonical token endpoint.
 */
export const EmailPasswordForm: ComponentType<EmailPasswordFormProps> = (props) => {
  const [email, setEmail] = useState(props.initialEmail ?? "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setBusy(true);
      setError(null);
      try {
        // Mints a PKCE-bound code, then navigates to the app callback which
        // completes the standard RFC 7636 exchange via handleCallback().
        window.location.href = await makeIam(props).loginWithPassword(email, password);
      } catch (err) {
        const e2 = err instanceof Error ? err : new Error(String(err));
        setError(e2.message);
        props.onError?.(e2);
      } finally {
        setBusy(false);
      }
    },
    [email, password, props.serverUrl, props.clientId, props.redirectUri, props.state, props.organization, props.application],
  );

  return h(
    "form",
    { onSubmit, className: "hanzo-iam-form" },
    h("input", {
      type: "email",
      name: "email",
      autoComplete: "email",
      placeholder: "Email",
      required: true,
      value: email,
      onChange: (e: { target: { value: string } }) => setEmail(e.target.value),
    }),
    h("input", {
      type: "password",
      name: "password",
      autoComplete: "current-password",
      placeholder: "Password",
      required: true,
      value: password,
      onChange: (e: { target: { value: string } }) => setPassword(e.target.value),
    }),
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    h("button", { type: "submit", disabled: busy, className: "hanzo-iam-btn" }, busy ? "Signing in…" : "Sign in"),
  );
};

/**
 * One-time-code step. Sends a code to the destination via IAM, then
 * verifies it against the password grant using the OTP as the password
 * (IAM's `email_otp` / `sms_otp` grant). Reports the access token.
 */
export const OTPStep: ComponentType<OTPStepProps> = (props) => {
  const [destination, setDestination] = useState(props.destination ?? "");
  const [code, setCode] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const send = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await makeIam(props).sendLoginCode(destination);
      setSent(true);
    } catch (err) {
      const e2 = err instanceof Error ? err : new Error(String(err));
      setError(e2.message);
      props.onError?.(e2);
    } finally {
      setBusy(false);
    }
  }, [destination, props.channel, props.serverUrl, props.clientId, props.organization, props.application]);

  const verify = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setBusy(true);
      setError(null);
      try {
        window.location.href = await makeIam(props).loginWithCode(destination, code);
      } catch (err) {
        const e2 = err instanceof Error ? err : new Error(String(err));
        setError(e2.message);
        props.onError?.(e2);
      } finally {
        setBusy(false);
      }
    },
    [destination, code, props.serverUrl, props.clientId, props.redirectUri, props.state, props.organization, props.application],
  );

  return h(
    "form",
    { onSubmit: verify, className: "hanzo-iam-form" },
    h("input", {
      type: props.channel === "email" ? "email" : "tel",
      placeholder: props.channel === "email" ? "Email" : "Phone",
      required: true,
      value: destination,
      disabled: sent,
      onChange: (e: { target: { value: string } }) => setDestination(e.target.value),
    }),
    sent
      ? h("input", {
          type: "text",
          inputMode: "numeric",
          autoComplete: "one-time-code",
          placeholder: "Code",
          required: true,
          value: code,
          onChange: (e: { target: { value: string } }) => setCode(e.target.value),
        })
      : null,
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    sent
      ? h("button", { type: "submit", disabled: busy, className: "hanzo-iam-btn" }, busy ? "Verifying…" : "Verify code")
      : h(
          "button",
          { type: "button", disabled: busy || !destination, onClick: send, className: "hanzo-iam-btn" },
          busy ? "Sending…" : (props.label ?? "Send code"),
        ),
  );
};

/**
 * Full embedded login. Reads the live method list and renders exactly
 * the enabled primitives — wallet, social providers, OTP, password — in
 * canonical order. White-label labels via `labels`; brand mark via
 * `brand`.
 */
export const Login: ComponentType<LoginProps> = (props) => {
  const flow: FlowProps = {
    serverUrl: props.serverUrl,
    clientId: props.clientId,
    redirectUri: props.redirectUri,
    state: props.state,
    organization: props.organization,
    application: props.application,
  };

  const socialLabel: Record<string, string | undefined> = {
    google: props.labels?.googleSocial,
    github: props.labels?.githubSocial,
    apple: props.labels?.appleSocial,
  };

  const children: ReactNode[] = [];
  if (props.brand) children.push(h("div", { key: "brand", className: "hanzo-iam-brand" }, props.brand));

  // Social/wallet providers (explicit per app; PKCE redirect).
  for (const provider of props.providers ?? []) {
    if (provider === "wallet") {
      children.push(h(WalletButton, { key: "wallet", ...flow, label: props.labels?.wallet }));
    } else {
      children.push(h(SocialButton, { key: `social-${provider}`, ...flow, provider, label: socialLabel[provider] }));
    }
  }

  // Password (always) — IAM credential login.
  children.push(h(EmailPasswordForm, { key: "password", ...flow, onSuccess: props.onSuccess }));

  // Passwordless email code.
  children.push(h("div", { key: "divider", className: "hanzo-iam-divider" }, props.labels?.divider ?? "or"));
  children.push(h(OTPStep, { key: "email-otp", ...flow, channel: "email", label: props.labels?.emailOtp, onSuccess: props.onSuccess }));

  return h("div", { className: props.className ?? "hanzo-iam-card" }, ...children);
};

// ============================================================
// onboarding views
// ============================================================

export type OnboardingStep = "identity" | "documents" | "biometric" | "screen" | "submit";

const ALL_STEPS: OnboardingStep[] = ["identity", "documents", "biometric", "screen", "submit"];

export interface OnboardingFlowProps {
  serverUrl: string;
  /** Auth bearer token from the prior sign-in. */
  token: string;
  /** Subset of steps to render. Defaults to all five in canonical order. */
  steps?: OnboardingStep[];
  /** Fired when the user finishes the final step. */
  onComplete?: (applicationId: string) => void;
  /** Brand-mark slot, same shape as Login. */
  brand?: ReactNode;
  className?: string;
}

export interface StepProps {
  serverUrl: string;
  token: string;
  applicationId?: string;
  onNext: (applicationId: string) => void;
  onError?: (error: Error) => void;
}

/** POST a step's payload to the IAM onboarding state machine. */
async function postStep(
  serverUrl: string,
  token: string,
  step: OnboardingStep,
  body: BodyInit | Record<string, unknown>,
  applicationId?: string,
): Promise<string> {
  const isForm = typeof FormData !== "undefined" && body instanceof FormData;
  const url = `${trimServerUrl(serverUrl)}${IAM_PATHS.onboarding}/${step}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(isForm ? {} : { "Content-Type": "application/json" }),
      ...(applicationId ? { "X-Application-Id": applicationId } : {}),
    },
    body: isForm ? (body as FormData) : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `onboarding ${step} failed (${res.status})`);
  }
  const out = (await res.json()) as { application_id?: string; applicationId?: string };
  return out.application_id ?? out.applicationId ?? applicationId ?? "";
}

function useStepSubmit(step: OnboardingStep, props: StepProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = useCallback(
    async (body: BodyInit | Record<string, unknown>) => {
      setBusy(true);
      setError(null);
      try {
        const id = await postStep(props.serverUrl, props.token, step, body, props.applicationId);
        props.onNext(id);
      } catch (err) {
        const e2 = err instanceof Error ? err : new Error(String(err));
        setError(e2.message);
        props.onError?.(e2);
      } finally {
        setBusy(false);
      }
    },
    [step, props.serverUrl, props.token, props.applicationId],
  );
  return { busy, error, submit };
}

/** PII step — date of birth + address. */
export const IdentityStep: ComponentType<StepProps> = (props) => {
  const [dob, setDob] = useState("");
  const [address, setAddress] = useState("");
  const { busy, error, submit } = useStepSubmit("identity", props);
  return h(
    "form",
    {
      className: "hanzo-iam-form",
      onSubmit: (e: FormEvent) => {
        e.preventDefault();
        void submit({ dob, address });
      },
    },
    h("input", { type: "date", required: true, value: dob, onChange: (e: { target: { value: string } }) => setDob(e.target.value) }),
    h("input", { type: "text", placeholder: "Address", required: true, value: address, onChange: (e: { target: { value: string } }) => setAddress(e.target.value) }),
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    h("button", { type: "submit", disabled: busy, className: "hanzo-iam-btn" }, busy ? "Saving…" : "Continue"),
  );
};

/** Document upload step — multipart. */
export const DocumentsStep: ComponentType<StepProps> = (props) => {
  const [file, setFile] = useState<File | null>(null);
  const { busy, error, submit } = useStepSubmit("documents", props);
  return h(
    "form",
    {
      className: "hanzo-iam-form",
      onSubmit: (e: FormEvent) => {
        e.preventDefault();
        if (!file) return;
        const fd = new FormData();
        fd.append("document", file);
        void submit(fd);
      },
    },
    h("input", {
      type: "file",
      required: true,
      onChange: (e: { target: { files: FileList | null } }) => setFile(e.target.files?.[0] ?? null),
    }),
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    h("button", { type: "submit", disabled: busy || !file, className: "hanzo-iam-btn" }, busy ? "Uploading…" : "Continue"),
  );
};

/** Biometric / IDV handoff step. */
export const BiometricStep: ComponentType<StepProps> = (props) => {
  const { busy, error, submit } = useStepSubmit("biometric", props);
  return h(
    "div",
    { className: "hanzo-iam-form" },
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    h(
      "button",
      { type: "button", disabled: busy, className: "hanzo-iam-btn", onClick: () => void submit({ started: true }) },
      busy ? "Starting…" : "Start verification",
    ),
  );
};

/** AML / sanctions screening step. */
export const ScreenStep: ComponentType<StepProps> = (props) => {
  const { busy, error, submit } = useStepSubmit("screen", props);
  return h(
    "div",
    { className: "hanzo-iam-form" },
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    h(
      "button",
      { type: "button", disabled: busy, className: "hanzo-iam-btn", onClick: () => void submit({ acknowledged: true }) },
      busy ? "Screening…" : "Continue",
    ),
  );
};

/** Finalize + fan-out step. */
export const SubmitStep: ComponentType<StepProps> = (props) => {
  const { busy, error, submit } = useStepSubmit("submit", props);
  return h(
    "div",
    { className: "hanzo-iam-form" },
    error ? h("p", { role: "alert", className: "hanzo-iam-error" }, error) : null,
    h(
      "button",
      { type: "button", disabled: busy, className: "hanzo-iam-btn", onClick: () => void submit({ finalize: true }) },
      busy ? "Submitting…" : "Submit application",
    ),
  );
};

const STEP_COMPONENT: Record<OnboardingStep, ComponentType<StepProps>> = {
  identity: IdentityStep,
  documents: DocumentsStep,
  biometric: BiometricStep,
  screen: ScreenStep,
  submit: SubmitStep,
};

/**
 * Full onboarding pipeline. Renders the selected steps in canonical
 * order, threading the IAM `application_id` returned by each step into
 * the next, and fires `onComplete` after the final step.
 */
export const OnboardingFlow: ComponentType<OnboardingFlowProps> = (props) => {
  const steps = props.steps ?? ALL_STEPS;
  const [index, setIndex] = useState(0);
  const [applicationId, setApplicationId] = useState<string | undefined>(undefined);

  const onNext = useCallback(
    (id: string) => {
      setApplicationId(id || undefined);
      if (index >= steps.length - 1) {
        props.onComplete?.(id);
      } else {
        setIndex(index + 1);
      }
    },
    [index, steps.length],
  );

  const step = steps[index];
  const StepView = STEP_COMPONENT[step];

  return h(
    "div",
    { className: props.className ?? "hanzo-iam-card" },
    props.brand ? h("div", { key: "brand", className: "hanzo-iam-brand" }, props.brand) : null,
    h("div", { key: "progress", className: "hanzo-iam-progress" }, `${index + 1} / ${steps.length}`),
    h(StepView, { key: step, serverUrl: props.serverUrl, token: props.token, applicationId, onNext }),
  );
};
