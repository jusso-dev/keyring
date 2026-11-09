import "server-only";
import type { AccessToken, TokenCredential } from "@azure/core-auth";
import type { AccountInfo, AuthenticationResult } from "@azure/msal-node";

export const VAULT_SCOPE = "https://vault.azure.net/.default";
export const ARM_SCOPE = "https://management.azure.com/.default";
export const LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default";

/** Refresh this long before a token runs out. */
export const REFRESH_MARGIN_MS = 5 * 60 * 1000;

/** The bits of MSAL the exchange needs. Keeps tests free of network calls. */
export type OboClient = {
  acquireTokenSilent(req: {
    account: AccountInfo;
    scopes: string[];
    forceRefresh?: boolean;
  }): Promise<AuthenticationResult>;
  acquireTokenOnBehalfOf(req: {
    oboAssertion: string;
    scopes: string[];
    claims?: string;
  }): Promise<AuthenticationResult | null>;
};

export type ReauthReason = "consent" | "conditional-access" | "expired";

/** Thrown when the person has to go through sign-in again before we can call Azure. */
export class ReauthRequiredError extends Error {
  readonly name = "ReauthRequiredError";
  constructor(
    readonly reason: ReauthReason,
    readonly claims?: string,
  ) {
    super(reauthMessage(reason));
  }
}

export function reauthMessage(reason: ReauthReason): string {
  switch (reason) {
    case "consent":
      return "Keyring needs permission to reach Azure for you. Ask your Entra ID admin to grant consent, then sign in again.";
    case "conditional-access":
      return "Your organisation needs you to sign in again, for example to confirm with MFA.";
    case "expired":
      return "Your sign-in has expired. Sign in again to carry on.";
  }
}

type MsalLikeError = {
  errorCode?: string;
  subError?: string;
  errorMessage?: string;
  claims?: string;
  name?: string;
};

/** Turns an MSAL error into a re-auth reason, or undefined if it isn't one. */
export function classifyAuthError(
  err: unknown,
): { reason: ReauthReason; claims?: string } | undefined {
  if (!err || typeof err !== "object") return undefined;
  const e = err as MsalLikeError;
  const text = `${e.errorCode ?? ""} ${e.subError ?? ""} ${e.errorMessage ?? ""}`;
  const claims = e.claims || undefined;
  if (/consent_required|AADSTS65001|AADSTS650057|invalid_resource/i.test(text)) {
    return { reason: "consent", claims };
  }
  if (
    claims ||
    /AADSTS50076|AADSTS50079|AADSTS53003|AADSTS50158|basic_action|additional_action/i.test(text)
  ) {
    return { reason: "conditional-access", claims };
  }
  if (
    e.name === "InteractionRequiredAuthError" ||
    /interaction_required|login_required|invalid_grant|no_tokens_found|no_account_in_silent_request|refresh_token_expired|AADSTS700082|AADSTS50173/i.test(
      text,
    )
  ) {
    return { reason: "expired", claims };
  }
  return undefined;
}

type Cached = { token: string; expiresAt: number };

/**
 * Exchanges the signed-in person's token for Azure tokens using on-behalf-of.
 * One per session. Tokens are kept in memory only and refreshed before expiry.
 */
export class OboTokenProvider {
  private readonly cache = new Map<string, Cached>();
  private readonly inflight = new Map<string, Promise<Cached>>();
  private readonly now: () => number;

  constructor(
    private readonly client: OboClient,
    private readonly account: AccountInfo,
    private readonly apiScope: string,
    now?: () => number,
  ) {
    this.now = now ?? Date.now;
  }

  async getToken(scope: string, options: { claims?: string } = {}): Promise<AccessToken> {
    const hit = this.cache.get(scope);
    if (!options.claims && hit && hit.expiresAt - REFRESH_MARGIN_MS > this.now()) {
      return { token: hit.token, expiresOnTimestamp: hit.expiresAt };
    }
    const key = options.claims ? `${scope}\u0000${options.claims}` : scope;
    let pending = this.inflight.get(key);
    if (!pending) {
      pending = this.exchange(scope, options.claims).finally(() => this.inflight.delete(key));
      this.inflight.set(key, pending);
    }
    const fresh = await pending;
    return { token: fresh.token, expiresOnTimestamp: fresh.expiresAt };
  }

  /** Drops cached tokens, for example after sign-out. */
  clear() {
    this.cache.clear();
  }

  private async exchange(scope: string, claims?: string): Promise<Cached> {
    try {
      // The user's token for Keyring's own API is the OBO assertion. MSAL
      // refreshes it from the in-memory cache when it's close to expiry.
      const user = await this.client.acquireTokenSilent({
        account: this.account,
        scopes: [this.apiScope],
      });
      if (!user?.accessToken) throw new ReauthRequiredError("expired");
      const result = await this.client.acquireTokenOnBehalfOf({
        oboAssertion: user.accessToken,
        scopes: [scope],
        ...(claims ? { claims } : {}),
      });
      if (!result?.accessToken || !result.expiresOn) throw new ReauthRequiredError("expired");
      const cached = { token: result.accessToken, expiresAt: result.expiresOn.getTime() };
      this.cache.set(scope, cached);
      return cached;
    } catch (err) {
      if (err instanceof ReauthRequiredError) throw err;
      const kind = classifyAuthError(err);
      if (kind) throw new ReauthRequiredError(kind.reason, kind.claims);
      throw err;
    }
  }
}

/**
 * Adapter so Azure SDK clients can use the OBO provider. It only accepts the
 * single scope it was made for, so one credential can't be pointed at another
 * resource by accident.
 */
export function oboCredential(provider: OboTokenProvider, scope: string): TokenCredential {
  return {
    async getToken(scopes, options) {
      const requested = Array.isArray(scopes) ? scopes : [scopes];
      if (requested.length !== 1 || requested[0] !== scope) {
        throw new Error(`This credential only issues tokens for ${scope}.`);
      }
      return provider.getToken(scope, { claims: options?.claims });
    },
  };
}
