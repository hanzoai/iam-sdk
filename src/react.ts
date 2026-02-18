/**
 * React bindings for @hanzo/iam.
 *
 * Provides a context provider, auth hooks, and org/project switching
 * that can be dropped into any React application.
 *
 * @example
 * ```tsx
 * import { IamProvider, useIam, useOrganizations } from '@hanzo/iam/react'
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
 *   const { user, isAuthenticated, login, logout } = useIam()
 *   const { organizations, currentOrg, switchOrg } = useOrganizations()
 *
 *   if (!isAuthenticated) return <button onClick={() => login()}>Log in</button>
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
import { BrowserIamSdk } from "./browser.js";
import type { BrowserIamConfig } from "./browser.js";
import { IamClient } from "./client.js";
import type { IamUser, IamOrganization, TokenResponse } from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IamProviderProps {
  /** Browser IAM SDK configuration. */
  config: BrowserIamConfig;
  /** Auto-initialize on mount (check stored tokens). Default: true. */
  autoInit?: boolean;
  /** Called when authentication state changes. */
  onAuthChange?: (authenticated: boolean) => void;
  children: ReactNode;
}

export interface IamContextValue {
  /** The underlying BrowserIamSdk instance for advanced use. */
  sdk: BrowserIamSdk;
  /** The IAM configuration. */
  config: BrowserIamConfig;
  /** Authenticated user (null if not logged in). */
  user: IamUser | null;
  /** Whether the user is currently authenticated. */
  isAuthenticated: boolean;
  /** Whether initial auth check is in progress. */
  isLoading: boolean;
  /** Current access token (null if not authenticated). */
  accessToken: string | null;
  /** Redirect to IAM login page. */
  login: (params?: { additionalParams?: Record<string, string> }) => Promise<void>;
  /** Open IAM login in a popup. */
  loginPopup: (params?: { width?: number; height?: number }) => Promise<void>;
  /** Handle OAuth callback — call on your /auth/callback route. */
  handleCallback: (callbackUrl?: string) => Promise<TokenResponse>;
  /** Log out and clear all tokens. */
  logout: () => void;
  /** Last auth error, if any. */
  error: Error | null;
}

export interface OrgState {
  /** All organizations the user belongs to. */
  organizations: IamOrganization[];
  /** Currently selected organization. */
  currentOrg: IamOrganization | null;
  /** Currently selected org ID. */
  currentOrgId: string | null;
  /** Switch to a different organization. */
  switchOrg: (orgId: string) => void;
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
IamContext.displayName = "HanzoIamContext";

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
 * Manages the BrowserIamSdk instance, token lifecycle, and auth state.
 */
export function IamProvider(props: IamProviderProps) {
  const { config, autoInit = true, onAuthChange, children } = props;

  const sdk = useMemo(
    () => new BrowserIamSdk(config),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [config.serverUrl, config.clientId, config.redirectUri],
  );

  const [user, setUser] = useState<IamUser | null>(null);
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
          setAccessToken(tokens.access_token);
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
        setAccessToken(tokens.access_token);
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
            if (!cancelled) setUser(info as unknown as IamUser);
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
    async (tokens: TokenResponse) => {
      setAccessToken(tokens.access_token);
      setIsAuthenticated(true);
      try {
        const info = await sdk.getUserInfo();
        setUser(info as unknown as IamUser);
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
 * Manage organization and project switching.
 *
 * Fetches the user's organizations from IAM and provides
 * `switchOrg` / `switchProject` to change the active tenant.
 * Selection is persisted to localStorage.
 */
export function useOrganizations(): OrgState {
  const { config, isAuthenticated, accessToken } = useIam();
  const [organizations, setOrganizations] = useState<IamOrganization[]>([]);
  const [isLoading, setIsLoading] = useState(false);

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

  // Fetch organizations when authenticated
  useEffect(() => {
    if (!isAuthenticated || !accessToken) {
      setOrganizations([]);
      return;
    }

    let cancelled = false;

    const fetchOrgs = async () => {
      setIsLoading(true);

      // 1. Parse JWT sub claim for primary org (immediate, no API call)
      try {
        const payload = JSON.parse(atob(accessToken.split(".")[1]));
        const sub = payload.sub as string;
        if (sub?.includes("/")) {
          const primaryOrg = sub.split("/")[0];
          if (!cancelled) {
            const syntheticOrg: IamOrganization = {
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
        }
      } catch {
        // Invalid token format — skip JWT parsing
      }

      // 2. Try to fetch full org list from API (may fail for non-admin users)
      try {
        const client = new IamClient({
          serverUrl: config.serverUrl,
          clientId: config.clientId,
        });
        const orgs = await client.getOrganizations(accessToken);
        if (!cancelled && orgs.length > 0) {
          setOrganizations(orgs);
          if (!currentOrgId && orgs.length > 0) {
            const firstOrg = orgs[0].name;
            setCurrentOrgId(firstOrg);
            try {
              localStorage.setItem(STORAGE_ORG_KEY, firstOrg);
            } catch {
              /* ok */
            }
          }
        }
      } catch {
        // API call failed — keep JWT-derived org
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    fetchOrgs();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, accessToken, config.serverUrl, config.clientId]);

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
    currentProjectId,
    switchProject,
    isLoading,
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
