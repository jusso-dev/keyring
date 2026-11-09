import "server-only";
import { getConfig } from "@/lib/config";
import { requireSession } from "./session";
import {
  ARM_SCOPE,
  LOG_ANALYTICS_SCOPE,
  OboTokenProvider,
  VAULT_SCOPE,
  oboCredential,
} from "./obo";
import type { Session } from "./session-store";

const PROVIDER = Symbol.for("keyring.obo.provider");
type WithProvider = Session & { [PROVIDER]?: OboTokenProvider };

/** The OBO provider for a session. Created once per session, kept in memory. */
export function oboProvider(session: Session): OboTokenProvider {
  const s = session as WithProvider;
  s[PROVIDER] ??= new OboTokenProvider(session.msal, session.account, getConfig().apiScope);
  return s[PROVIDER];
}

/**
 * Credentials for the signed-in person. Build Azure SDK clients from these on
 * every request. There is no app-only or managed identity fallback.
 */
export async function userCredentials() {
  const session = await requireSession();
  const provider = oboProvider(session);
  return {
    session,
    keyVault: oboCredential(provider, VAULT_SCOPE),
    arm: oboCredential(provider, ARM_SCOPE),
    logAnalytics: oboCredential(provider, LOG_ANALYTICS_SCOPE),
  };
}
