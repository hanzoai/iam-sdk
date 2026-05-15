import * as react from 'react';
import { ReactNode } from 'react';
import { IAM, IAMConfig, IAMToken } from './browser.cjs';
import { IamUser, IamOrganization, IamProject } from './types.cjs';

interface IamProviderProps {
    /** Browser IAM SDK configuration. */
    config: IAMConfig;
    /** Auto-initialize on mount (check stored tokens). Default: true. */
    autoInit?: boolean;
    /** Called when authentication state changes. */
    onAuthChange?: (authenticated: boolean) => void;
    children: ReactNode;
}
interface IamContextValue {
    /** The underlying IAM instance for advanced use. */
    sdk: IAM;
    /** The IAM configuration. */
    config: IAMConfig;
    /** Authenticated user (null if not logged in). */
    user: IamUser | null;
    /** Whether the user is currently authenticated. */
    isAuthenticated: boolean;
    /** Whether initial auth check is in progress. */
    isLoading: boolean;
    /** Current access token (null if not authenticated). */
    accessToken: string | null;
    /** Redirect to IAM login page. */
    login: (params?: {
        additionalParams?: Record<string, string>;
    }) => Promise<void>;
    /** Open IAM login in a popup. */
    loginPopup: (params?: {
        width?: number;
        height?: number;
    }) => Promise<void>;
    /** Handle OAuth callback — call on your /auth/callback route. */
    handleCallback: (callbackUrl?: string) => Promise<IAMToken>;
    /** Log out and clear all tokens. */
    logout: () => void;
    /** Last auth error, if any. */
    error: Error | null;
}
interface OrgState {
    /** All organizations the user belongs to. */
    organizations: IamOrganization[];
    /** Currently selected organization. */
    currentOrg: IamOrganization | null;
    /** Currently selected org ID. */
    currentOrgId: string | null;
    /** Switch to a different organization. */
    switchOrg: (orgId: string) => void;
    /** All projects for the current organization. */
    projects: IamProject[];
    /** Currently selected project. */
    currentProject: IamProject | null;
    /** Currently selected project ID within the org. */
    currentProjectId: string | null;
    /** Switch to a different project (null to clear). */
    switchProject: (projectId: string | null) => void;
    /** Whether organizations are loading. */
    isLoading: boolean;
}
declare const IamContext: react.Context<IamContextValue | null>;
/**
 * Root provider for Hanzo IAM in React applications.
 *
 * Wrap your app (or a subtree) with this provider to enable IAM auth.
 * Manages the IAM instance, token lifecycle, and auth state.
 */
declare function IamProvider(props: IamProviderProps): react.FunctionComponentElement<react.ProviderProps<IamContextValue | null>>;
/**
 * Access Hanzo IAM auth state and methods.
 * Must be used within an `<IamProvider>`.
 */
declare function useIam(): IamContextValue;
/**
 * Manage organization switching, derived from the JWT `sub`/`owner`
 * claims. Project state is preserved as an empty list — apps that
 * need full org/project listings must query their own admin API.
 *
 * Selection is persisted to localStorage.
 */
declare function useOrganizations(): OrgState;
/**
 * Hook that provides a valid access token with auto-refresh capability.
 * Returns null while loading or if not authenticated.
 */
declare function useIamToken(): {
    token: string | null;
    isValid: boolean;
    refresh: () => Promise<string | null>;
};

interface OrgProjectSwitcherProps {
    organizations: Array<{
        name: string;
        displayName?: string;
        owner?: string;
    }>;
    currentOrgId: string | null;
    switchOrg: (orgId: string) => void;
    projects?: Array<{
        name: string;
        displayName?: string;
        organization?: string;
        isDefault?: boolean;
    }>;
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
declare function OrgProjectSwitcher({ organizations, currentOrgId, switchOrg, projects, currentProjectId, switchProject, onTenantChange, environment, className, alwaysShow, }: OrgProjectSwitcherProps): react.DetailedReactHTMLElement<{
    className: string;
}, HTMLElement> | null;

export { IamContext, type IamContextValue, IamProvider, type IamProviderProps, OrgProjectSwitcher, type OrgProjectSwitcherProps, type OrgState, useIam, useIamToken, useOrganizations };
