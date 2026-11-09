import "server-only";
import { CryptoProvider, type ConfidentialClientApplication } from "@azure/msal-node";
import type { Config } from "@/lib/config";
import { newId } from "./cookie";
import { redirectUri, signInScopes } from "./msal";
import { safeReturnTo } from "./return-to";
import type { AuthFlow, Session, SessionUser } from "./session-store";

const crypto = new CryptoProvider();

export type MsalFactory = (config: Config) => ConfidentialClientApplication;

/** Step one: build the Entra sign-in URL and the flow state we need to finish it. */
export async function beginSignIn(
  config: Config,
  msal: ConfidentialClientApplication,
  returnTo: string | null,
  claims?: string | null,
): Promise<{ url: string; flowId: string; flow: AuthFlow }> {
  const { verifier, challenge } = await crypto.generatePkceCodes();
  const flow: AuthFlow = {
    state: newId(),
    nonce: newId(),
    codeVerifier: verifier,
    returnTo: safeReturnTo(returnTo),
  };
  const url = await msal.getAuthCodeUrl({
    scopes: signInScopes(config),
    redirectUri: redirectUri(config),
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
    state: flow.state,
    nonce: flow.nonce,
    responseMode: "query",
    // A claims challenge (conditional access) needs a fresh prompt for that
    // specific requirement rather than the account picker.
    ...(claims ? { claims } : { prompt: "select_account" }),
  });
  return { url, flowId: newId(), flow };
}

export type CallbackParams = {
  code: string | null;
  state: string | null;
  clientInfo: string | null;
  error: string | null;
  errorDescription: string | null;
};

export class SignInError extends Error {
  constructor(
    readonly reason: "cancelled" | "state" | "failed" | "consent",
    message: string,
  ) {
    super(message);
  }
}

/** Step two: check the response from Entra and swap the code for tokens. */
export async function completeSignIn(
  config: Config,
  msal: ConfidentialClientApplication,
  flow: AuthFlow | undefined,
  params: CallbackParams,
): Promise<Omit<Session, "prefs">> {
  if (params.error) {
    if (params.error === "access_denied") {
      throw new SignInError("cancelled", "Sign-in was cancelled.");
    }
    if (params.error === "consent_required" || params.error === "interaction_required") {
      throw new SignInError("consent", "Your organisation needs to approve Keyring first.");
    }
    throw new SignInError("failed", "Sign-in didn't work.");
  }
  if (!flow || !params.state || params.state !== flow.state || !params.code) {
    throw new SignInError("state", "That sign-in link has expired.");
  }
  const result = await msal.acquireTokenByCode(
    {
      code: params.code,
      scopes: signInScopes(config),
      redirectUri: redirectUri(config),
      codeVerifier: flow.codeVerifier,
      state: flow.state,
      nonce: flow.nonce,
    },
    {
      code: params.code,
      state: params.state,
      nonce: flow.nonce,
      ...(params.clientInfo ? { client_info: params.clientInfo } : {}),
    },
  );
  if (!result.account) throw new SignInError("failed", "Sign-in didn't work.");
  const claims = result.idTokenClaims as Record<string, unknown>;
  const user: SessionUser = {
    name: String(claims.name ?? result.account.name ?? result.account.username),
    username: result.account.username,
    oid: String(claims.oid ?? result.account.localAccountId),
    tenantId: result.account.tenantId,
  };
  return { id: newId(), user, account: result.account, msal };
}
