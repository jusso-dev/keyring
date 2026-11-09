import "server-only";
import type { AccountInfo, ConfidentialClientApplication } from "@azure/msal-node";
import { TtlStore } from "./ttl-store";

export type SessionUser = {
  name: string;
  username: string;
  oid: string;
  tenantId: string;
};

export type Session = {
  id: string;
  user: SessionUser;
  account: AccountInfo;
  msal: ConfidentialClientApplication;
  /** Small per-session values such as the last vault picked. Never secret values. */
  prefs: Record<string, string>;
};

export type AuthFlow = {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
};

export const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 60 * 60 * 1000;
export const AUTH_FLOW_MS = 10 * 60 * 1000;

type Stores = { sessions: TtlStore<Session>; flows: TtlStore<AuthFlow> };

// Route handlers, server components and actions can be bundled separately,
// so the stores hang off globalThis to make sure everyone shares one copy.
const KEY = Symbol.for("keyring.auth.stores");
const g = globalThis as typeof globalThis & { [KEY]?: Stores };

export function stores(): Stores {
  g[KEY] ??= {
    sessions: new TtlStore<Session>({ absoluteMs: SESSION_ABSOLUTE_MS, idleMs: SESSION_IDLE_MS }),
    flows: new TtlStore<AuthFlow>({ absoluteMs: AUTH_FLOW_MS, idleMs: AUTH_FLOW_MS }),
  };
  return g[KEY];
}
