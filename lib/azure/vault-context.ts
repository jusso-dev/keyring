import "server-only";
import { userCredentials } from "@/lib/auth/azure-credential";
import type { Session } from "@/lib/auth/session-store";
import { listVaults, resourceGraphClient, type Vault } from "./vaults";

/** Vault metadata is kept briefly per session so the picker doesn't re-query on every page. */
const VAULT_LIST_TTL_MS = 2 * 60 * 1000;
const CACHE = Symbol.for("keyring.vaults.cache");
type WithCache = Session & { [CACHE]?: { at: number; vaults: Vault[] } };

export const LAST_VAULT_PREF = "lastVault";

/** Every vault the person can see. Throws Azure errors for the caller to show. */
export async function getVaults(options: { fresh?: boolean } = {}): Promise<Vault[]> {
  const { session, arm } = await userCredentials();
  const s = session as WithCache;
  const hit = s[CACHE];
  if (!options.fresh && hit && Date.now() - hit.at < VAULT_LIST_TTL_MS) return hit.vaults;
  const vaults = await listVaults(resourceGraphClient(arm));
  s[CACHE] = { at: Date.now(), vaults };
  return vaults;
}

export async function findVault(name: string): Promise<Vault | undefined> {
  const lower = name.toLowerCase();
  return (await getVaults()).find((v) => v.name.toLowerCase() === lower);
}

export function rememberVault(session: Session, name: string) {
  session.prefs[LAST_VAULT_PREF] = name;
}

export function lastVault(session: Session): string | undefined {
  return session.prefs[LAST_VAULT_PREF];
}
