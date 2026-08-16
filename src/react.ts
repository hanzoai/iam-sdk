/**
 * React bindings for @hanzo/iam.
 *
 * Provides a context provider, auth hooks, org/project switching, and the
 * embedded `<Login>` component — the DEFAULT login UI apps should mount.
 * `<Login>` (re-exported here from `@hanzo/iam/views`) keeps every method
 * in-place: social via popup + postMessage, wallet via inline SIWx,
 * email/password/OTP via PKCE-bound code. It never full-page redirects to
 * the hosted login page. `signinRedirect` (surfaced as `useIam().login`)
 * remains available only as an explicit standalone fallback.
 *
 * @example
 * ```tsx
 * import { IamProvider, Login, useIam } from '@hanzo/iam/react'
 *
 * function App() {
 *   return (
 *     <IamProvider config={{
 *       serverUrl: 'https://iam.hanzo.ai',
 *       clientId: 'my-app',
 *       redirectUri: `${window.location.origin}/auth/callback`,
 *     }}>
 *       <MyApp />
 *     </IamProvider>
 *   )
 * }
 *
 * function MyApp() {
 *   const { user, isAuthenticated } = useIam()
 *   // Embedded, in-place — the default. Not a redirect.
 *   if (!isAuthenticated)
 *     return <Login serverUrl="https://iam.hanzo.ai" clientId="my-app"
 *                   redirectUri={`${location.origin}/auth/callback`} state=""
 *                   providers={['google','github','wallet']} />
 *   return <div>Welcome, {user?.displayName}</div>
 * }
 * ```
 *
 * @packageDocumentation
 */

import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { IAM } from "./browser.js";
import type { IAMConfig } from "./browser.js";
import type { User, Organization, Project } from "./types.js";
import type { IAMToken } from "./browser.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IamProviderProps {
  /** Browser IAM SDK configuration. */
  config: IAMConfig;
  /** Auto-initialize on mount (check stored tokens). Default: true. */
  autoInit?: boolean;
  /** Called when authentication state changes. */
  onAuthChange?: (authenticated: boolean) => void;
  children: ReactNode;
}

export interface IamContextValue {
  /** The underlying IAM instance for advanced use. */
  sdk: IAM;
  /** The IAM configuration. */
  config: IAMConfig;
  /** Authenticated user (null if not logged in). */
  user: User | null;
  /** Whether the user is currently authenticated. */
  isAuthenticated: boolean;
  /** Whether initial auth check is in progress. */
  isLoading: boolean;
  /** Current access token (null if not authenticated). */
  accessToken: string | null;
  /**
   * Explicit standalone FALLBACK: full-page redirect to the hosted login
   * page. Not the default — prefer the embedded `<Login>` component or
   * `loginPopup` so login stays in-place.
   */
  login: (params?: { additionalParams?: Record<string, string> }) => Promise<void>;
  /** In-place social login via popup + postMessage. Resolves once signed in. */
  loginPopup: (params?: { width?: number; height?: number }) => Promise<void>;
  /** Handle OAuth callback — call on your /auth/callback route. */
  handleCallback: (callbackUrl?: string) => Promise<IAMToken>;
  /** Log out and clear all tokens. */
  logout: () => void;
  /** Last auth error, if any. */
  error: Error | null;
}

export interface OrgState {
  /** All organizations the user belongs to. */
  organizations: Organization[];
  /** Currently selected organization. */
  currentOrg: Organization | null;
  /** Currently selected org ID. */
  currentOrgId: string | null;
  /** Switch to a different organization. */
  switchOrg: (orgId: string) => void;
  /** All projects for the current organization. */
  projects: Project[];
  /** Currently selected project. */
  currentProject: Project | null;
  /** Currently selected project ID within the org. */
  currentProjectId: string | null;
  /** Switch to a different project (null to clear). */
  switchProject: (projectId: string | null) => void;
  /** Whether organizations are loading. */
  isLoading: boolean;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const IamContext = createContext<IamContextValue | null>(null);
IamContext.displayName = "IamContext";

// Storage keys for tenant persistence
const STORAGE_ORG_KEY = "hanzo_iam_current_org";
const STORAGE_PROJECT_KEY = "hanzo_iam_current_project";
const STORAGE_EXPIRES_KEY = "hanzo_iam_expires_at";

// ---------------------------------------------------------------------------
// IamProvider
// ---------------------------------------------------------------------------

/**
 * Root provider for Hanzo IAM in React applications.
 *
 * Wrap your app (or a subtree) with this provider to enable IAM auth.
 * Manages the IAM instance, token lifecycle, and auth state.
 */
export function IamProvider(props: IamProviderProps) {
  const { config, autoInit = true, onAuthChange, children } = props;

  const sdk = useMemo(
    () => new IAM(config),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [config.serverUrl, config.clientId, config.redirectUri],
  );

  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(autoInit);
  const [accessToken, setAccessToken] = useState<string | null>(
    sdk.getAccessToken(),
  );
  const [error, setError] = useState<Error | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Schedule token refresh ~60s before expiry
  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    if (sdk.isTokenExpired()) return;

    const storage = config.storage ?? sessionStorage;
    const expiresAtStr = storage.getItem(STORAGE_EXPIRES_KEY);
    if (!expiresAtStr) return;

    const msUntilRefresh = Number(expiresAtStr) - Date.now() - 60_000;
    if (msUntilRefresh <= 0) {
      sdk
        .refreshAccessToken()
        .then((tokens) => {
          setAccessToken(tokens.accessToken);
          scheduleRefresh();
        })
        .catch(() => {
          setIsAuthenticated(false);
          setUser(null);
          setAccessToken(null);
        });
      return;
    }

    refreshTimerRef.current = setTimeout(async () => {
      try {
        const tokens = await sdk.refreshAccessToken();
        setAccessToken(tokens.accessToken);
        scheduleRefresh();
      } catch {
        setIsAuthenticated(false);
        setUser(null);
        setAccessToken(null);
      }
    }, msUntilRefresh);
  }, [sdk, config.storage]);

  // Auto-init: check stored tokens on mount
  useEffect(() => {
    if (!autoInit) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;

    const init = async () => {
      try {
        const token = await sdk.getValidAccessToken();
        if (cancelled) return;
        if (token) {
          setAccessToken(token);
          setIsAuthenticated(true);
          try {
            const info = await sdk.getUserInfo();
            if (!cancelled) setUser(info as unknown as User);
          } catch {
            // Token valid but userinfo failed — still authenticated
          }
          scheduleRefresh();
          onAuthChange?.(true);
        } else {
          onAuthChange?.(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error(String(err)));
          onAuthChange?.(false);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    init();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sdk, autoInit]);

  // Cleanup refresh timer on unmount
  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    };
  }, []);

  // Complete authentication after login/callback
  const completeAuth = useCallback(
    async (tokens: IAMToken) => {
      setAccessToken(tokens.accessToken);
      setIsAuthenticated(true);
      try {
        const info = await sdk.getUserInfo();
        setUser(info as unknown as User);
      } catch {
        // ok — token valid, userinfo is optional
      }
      scheduleRefresh();
      onAuthChange?.(true);
    },
    [sdk, scheduleRefresh, onAuthChange],
  );

  const login = useCallback(
    async (params?: { additionalParams?: Record<string, string> }) => {
      setError(null);
      await sdk.signinRedirect(params);
    },
    [sdk],
  );

  const loginPopup = useCallback(
    async (params?: { width?: number; height?: number }) => {
      setError(null);
      try {
        const tokens = await sdk.signinPopup(params);
        await completeAuth(tokens);
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      }
    },
    [sdk, completeAuth],
  );

  const handleCallback = useCallback(
    async (callbackUrl?: string) => {
      setError(null);
      try {
        const tokens = await sdk.handleCallback(callbackUrl);
        await completeAuth(tokens);
        return tokens;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      }
    },
    [sdk, completeAuth],
  );

  const logout = useCallback(() => {
    sdk.clearTokens();
    setUser(null);
    setIsAuthenticated(false);
    setAccessToken(null);
    setError(null);
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    try {
      localStorage.removeItem(STORAGE_ORG_KEY);
      localStorage.removeItem(STORAGE_PROJECT_KEY);
    } catch {
      /* ok */
    }
    onAuthChange?.(false);
  }, [sdk, onAuthChange]);

  const value = useMemo<IamContextValue>(
    () => ({
      sdk,
      config,
      user,
      isAuthenticated,
      isLoading,
      accessToken,
      login,
      loginPopup,
      handleCallback,
      logout,
      error,
    }),
    [
      sdk,
      config,
      user,
      isAuthenticated,
      isLoading,
      accessToken,
      login,
      loginPopup,
      handleCallback,
      logout,
      error,
    ],
  );

  return createElement(IamContext.Provider, { value }, children);
}

// ---------------------------------------------------------------------------
// useIam
// ---------------------------------------------------------------------------

/**
 * Access Hanzo IAM auth state and methods.
 * Must be used within an `<IamProvider>`.
 */
export function useIam(): IamContextValue {
  const ctx = useContext(IamContext);
  if (!ctx) {
    throw new Error("useIam() must be used within an <IamProvider>");
  }
  return ctx;
}

// ---------------------------------------------------------------------------
// useOrganizations
// ---------------------------------------------------------------------------

/**
 * Manage organization switching, derived from the JWT `sub`/`owner`
 * claims. Project state is preserved as an empty list — apps that
 * need full org/project listings must query their own admin API.
 *
 * Selection is persisted to localStorage.
 */
export function useOrganizations(): OrgState {
  const { isAuthenticated, accessToken } = useIam();
  const [organizations, setOrganizations] = useState<Organization[]>([]);

  const [currentOrgId, setCurrentOrgId] = useState<string | null>(() => {
    try {
      return localStorage.getItem(STORAGE_ORG_KEY);
    } catch {
      return null;
    }
  });

  const [currentProjectId, setCurrentProjectId] = useState<string | null>(
    () => {
      try {
        return localStorage.getItem(STORAGE_PROJECT_KEY);
      } catch {
        return null;
      }
    },
  );

  // Derive primary org from the JWT (sub="org/username" or owner claim).
  // No API call — this SDK never queries a legacy get-organizations verb
  // admin surface. Apps that need a multi-org list must fetch it from
  // their own admin/control-plane API.
  useEffect(() => {
    if (!isAuthenticated || !accessToken) {
      setOrganizations([]);
      return;
    }
    try {
      const payload = JSON.parse(atob(accessToken.split(".")[1]));
      const sub = (payload.sub as string) || "";
      const owner = (payload.owner as string) || "";
      const primaryOrg = owner || (sub.includes("/") ? sub.split("/")[0] : "");
      if (primaryOrg) {
        const syntheticOrg: Organization = {
          owner: "admin",
          name: primaryOrg,
          displayName: primaryOrg,
        };
        setOrganizations([syntheticOrg]);
        if (!currentOrgId) {
          setCurrentOrgId(primaryOrg);
          try {
            localStorage.setItem(STORAGE_ORG_KEY, primaryOrg);
          } catch {
            /* ok */
          }
        }
      }
    } catch {
      // Invalid token format — leave organizations empty
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, accessToken]);

  const projects: Project[] = [];
  const currentProject: Project | null = null;

  const currentOrg = useMemo(
    () => organizations.find((o) => o.name === currentOrgId) ?? null,
    [organizations, currentOrgId],
  );

  const switchOrg = useCallback((orgId: string) => {
    setCurrentOrgId(orgId);
    setCurrentProjectId(null);
    try {
      localStorage.setItem(STORAGE_ORG_KEY, orgId);
      localStorage.removeItem(STORAGE_PROJECT_KEY);
    } catch {
      /* ok */
    }
  }, []);

  const switchProject = useCallback((projectId: string | null) => {
    setCurrentProjectId(projectId);
    try {
      if (projectId) {
        localStorage.setItem(STORAGE_PROJECT_KEY, projectId);
      } else {
        localStorage.removeItem(STORAGE_PROJECT_KEY);
      }
    } catch {
      /* ok */
    }
  }, []);

  return {
    organizations,
    currentOrg,
    currentOrgId,
    switchOrg,
    projects,
    currentProject,
    currentProjectId,
    switchProject,
    isLoading: false,
  };
}

// ---------------------------------------------------------------------------
// useIamToken
// ---------------------------------------------------------------------------

/**
 * Hook that provides a valid access token with auto-refresh capability.
 * Returns null while loading or if not authenticated.
 */
export function useIamToken(): {
  token: string | null;
  isValid: boolean;
  refresh: () => Promise<string | null>;
} {
  const { sdk, accessToken, isAuthenticated } = useIam();

  const refresh = useCallback(async () => {
    try {
      return await sdk.getValidAccessToken();
    } catch {
      return null;
    }
  }, [sdk]);

  return {
    token: accessToken,
    isValid: isAuthenticated && !!accessToken && !sdk.isTokenExpired(),
    refresh,
  };
}

// Re-export context for advanced use
export { IamContext };

// ---------------------------------------------------------------------------
// OrgProjectSwitcher component
// ---------------------------------------------------------------------------

export interface OrgProjectSwitcherProps {
  organizations: Array<{ name: string; displayName?: string; owner?: string }>;
  currentOrgId: string | null;
  switchOrg: (orgId: string) => void;
  projects?: Array<{ name: string; displayName?: string; organization?: string; isDefault?: boolean }>;
  currentProjectId?: string | null;
  switchProject?: (projectId: string | null) => void;
  onTenantChange?: (orgId: string | null, projectId: string | null) => void;
  environment?: string | null;
  className?: string;
  alwaysShow?: boolean;
}

/**
 * Organization and project switcher component.
 *
 * @example
 * ```tsx
 * import { useOrganizations, OrgProjectSwitcher } from '@hanzo/iam/react'
 *
 * function Nav() {
 *   const orgState = useOrganizations()
 *   return <OrgProjectSwitcher {...orgState} />
 * }
 * ```
 */
export function OrgProjectSwitcher({
  organizations,
  currentOrgId,
  switchOrg,
  projects = [],
  currentProjectId = null,
  switchProject,
  onTenantChange,
  environment,
  className = "",
  alwaysShow = false,
}: OrgProjectSwitcherProps) {
  useEffect(() => {
    onTenantChange?.(currentOrgId, currentProjectId ?? null);
  }, [currentOrgId, currentProjectId, onTenantChange]);

  const handleOrgChange = useCallback(
    (e: { target: { value: string } }) => switchOrg(e.target.value),
    [switchOrg],
  );

  const handleProjectChange = useCallback(
    (e: { target: { value: string } }) => switchProject?.(e.target.value || null),
    [switchProject],
  );

  if (!alwaysShow && organizations.length <= 1 && projects.length <= 1) {
    if (organizations.length === 1) {
      const org = organizations[0];
      return createElement(
        "div",
        { className: `flex items-center gap-2 text-sm ${className}` },
        createElement("span", { className: "font-medium" }, org.displayName || org.name),
        projects.length === 1
          ? [
              createElement("span", { className: "text-muted-foreground", key: "sep" }, "/"),
              createElement("span", { key: "proj" }, projects[0].displayName || projects[0].name),
            ]
          : null,
        environment
          ? createElement(
              "span",
              { className: "rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground" },
              environment,
            )
          : null,
      );
    }
    return null;
  }

  return createElement(
    "div",
    { className: `flex items-center gap-2 ${className}` },
    createElement(
      "select",
      {
        value: currentOrgId ?? "",
        onChange: handleOrgChange,
        className:
          "h-8 rounded-md border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring",
        "aria-label": "Switch organization",
      },
      ...organizations.map((org) =>
        createElement("option", { key: org.name, value: org.name }, org.displayName || org.name),
      ),
    ),
    projects.length > 0 && switchProject
      ? [
          createElement("span", { className: "text-muted-foreground", key: "sep" }, "/"),
          createElement(
            "select",
            {
              key: "proj-select",
              value: currentProjectId ?? "",
              onChange: handleProjectChange,
              className:
                "h-8 rounded-md border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring",
              "aria-label": "Switch project",
            },
            ...projects.map((proj) =>
              createElement("option", { key: proj.name, value: proj.name }, proj.displayName || proj.name),
            ),
          ),
        ]
      : null,
    environment
      ? createElement(
          "span",
          { className: "rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground" },
          environment,
        )
      : null,
  );
}

// ---------------------------------------------------------------------------
// Embedded login surface — the DEFAULT the /react entry hands apps.
//
// `<Login>` is the one login UI: in-place social (popup + postMessage),
// in-place wallet (inline SIWx), and PKCE-bound email/password/OTP. Apps
// import it straight from "@hanzo/iam/react" instead of reaching for
// `signinRedirect`. `completePopupSignin` is the popup callback-page bridge,
// re-exported so the same entry covers the whole flow.
// ---------------------------------------------------------------------------

export {
  Login,
  SocialButton,
  WalletButton,
  EmailPasswordForm,
  OTPStep,
  useAuthMethods,
  OnboardingFlow,
  type LoginProps,
  type SocialButtonProps,
  type WalletButtonProps,
  type EmailPasswordFormProps,
  type OTPStepProps,
  type AuthMethod,
  type AuthMethodKind,
  type MethodsResponse,
  type MethodsView,
  type FlowProps,
} from "./views.js";

export { completePopupSignin } from "./browser.js";
