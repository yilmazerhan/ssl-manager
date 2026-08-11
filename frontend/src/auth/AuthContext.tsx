import { createContext, useContext, useMemo, useState, ReactNode } from "react";

export type Role = "viewer" | "cert_manager" | "admin" | "api_only";

export interface Identity {
  userId: string;
  email: string;
  role: Role;
  team: string;
}

const ROLE_SCOPES: Record<Role, string[]> = {
  viewer: ["certs:read"],
  cert_manager: ["certs:read", "certs:export", "certs:issue"],
  admin: ["certs:read", "certs:export", "certs:issue", "certs:admin"],
  api_only: [],
};

interface AuthState {
  token: string | null;
  identity: Identity | null;
  login: (token: string) => void;
  logout: () => void;
  hasScope: (scope: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

const STORAGE_KEY = "ssl-sentry.token";

function decodeIdentity(token: string): Identity | null {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { userId: payload.sub, email: payload.email, role: payload.role, team: payload.team ?? "" };
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => {
    const fromURL = new URLSearchParams(window.location.search).get("token");
    if (fromURL) {
      window.history.replaceState({}, "", window.location.pathname);
      localStorage.setItem(STORAGE_KEY, fromURL);
      return fromURL;
    }
    return localStorage.getItem(STORAGE_KEY);
  });

  const identity = useMemo(() => (token ? decodeIdentity(token) : null), [token]);

  // localStorage is written here, synchronously, rather than in a useEffect
  // keyed on `token`: React runs child effects before parent effects within
  // the same commit, so a child's data fetch (reading localStorage directly
  // in api/client.ts) can otherwise run before this provider's own effect
  // had a chance to persist the token, see it missing, and 401.
  const value: AuthState = {
    token,
    identity,
    login: (newToken: string) => {
      localStorage.setItem(STORAGE_KEY, newToken);
      setToken(newToken);
    },
    logout: () => {
      localStorage.removeItem(STORAGE_KEY);
      setToken(null);
    },
    hasScope: (scope: string) => (identity ? ROLE_SCOPES[identity.role]?.includes(scope) ?? false : false),
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
