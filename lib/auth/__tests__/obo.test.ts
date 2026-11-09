import type { AccountInfo, AuthenticationResult } from "@azure/msal-node";
import { describe, expect, it, vi } from "vitest";
import {
  ARM_SCOPE,
  OboTokenProvider,
  ReauthRequiredError,
  VAULT_SCOPE,
  classifyAuthError,
  oboCredential,
  type OboClient,
} from "../obo";

const account = { homeAccountId: "h", username: "alex@example.com" } as AccountInfo;
const API = "api://client/access_as_user";

function client(opts: { lifetimeMs?: number; oboError?: unknown; silentError?: unknown } = {}) {
  let n = 0;
  let now = 1_000_000;
  const c = {
    acquireTokenSilent: vi.fn(async () => {
      if (opts.silentError) throw opts.silentError;
      return { accessToken: "user-token" } as AuthenticationResult;
    }),
    acquireTokenOnBehalfOf: vi.fn(async (req: { scopes: string[] }) => {
      if (opts.oboError) throw opts.oboError;
      n++;
      return {
        accessToken: `${req.scopes[0]}#${n}`,
        expiresOn: new Date(now + (opts.lifetimeMs ?? 60 * 60 * 1000)),
      } as AuthenticationResult;
    }),
  };
  return {
    c: c as OboClient & typeof c,
    clock: () => now,
    advance: (ms: number) => (now += ms),
  };
}

describe("OboTokenProvider", () => {
  it("exchanges the user's token for the requested resource", async () => {
    const { c, clock } = client();
    const p = new OboTokenProvider(c, account, API, clock);
    const t = await p.getToken(VAULT_SCOPE);
    expect(t.token).toBe(`${VAULT_SCOPE}#1`);
    expect(c.acquireTokenSilent).toHaveBeenCalledWith({ account, scopes: [API] });
    expect(c.acquireTokenOnBehalfOf).toHaveBeenCalledWith({
      oboAssertion: "user-token",
      scopes: [VAULT_SCOPE],
    });
  });

  it("caches per resource", async () => {
    const { c, clock } = client();
    const p = new OboTokenProvider(c, account, API, clock);
    await p.getToken(VAULT_SCOPE);
    await p.getToken(VAULT_SCOPE);
    await p.getToken(ARM_SCOPE);
    expect(c.acquireTokenOnBehalfOf).toHaveBeenCalledTimes(2);
  });

  it("refreshes before expiry", async () => {
    const { c, clock, advance } = client({ lifetimeMs: 10 * 60 * 1000 });
    const p = new OboTokenProvider(c, account, API, clock);
    await p.getToken(VAULT_SCOPE);
    advance(4 * 60 * 1000);
    expect((await p.getToken(VAULT_SCOPE)).token).toBe(`${VAULT_SCOPE}#1`);
    advance(2 * 60 * 1000); // now inside the 5 minute margin
    expect((await p.getToken(VAULT_SCOPE)).token).toBe(`${VAULT_SCOPE}#2`);
  });

  it("shares one exchange between concurrent callers", async () => {
    const { c, clock } = client();
    const p = new OboTokenProvider(c, account, API, clock);
    await Promise.all([p.getToken(VAULT_SCOPE), p.getToken(VAULT_SCOPE)]);
    expect(c.acquireTokenOnBehalfOf).toHaveBeenCalledTimes(1);
  });

  it("maps consent errors", async () => {
    const { c, clock } = client({
      oboError: {
        errorCode: "invalid_grant",
        errorMessage: "AADSTS65001: The user or administrator has not consented",
      },
    });
    const p = new OboTokenProvider(c, account, API, clock);
    await expect(p.getToken(VAULT_SCOPE)).rejects.toMatchObject({ reason: "consent" });
  });

  it("maps conditional access challenges and keeps the claims", async () => {
    const claims = '{"access_token":{"capolids":{"essential":true,"values":["x"]}}}';
    const { c, clock } = client({
      oboError: { errorCode: "invalid_grant", errorMessage: "AADSTS50076: MFA required", claims },
    });
    const p = new OboTokenProvider(c, account, API, clock);
    const err = await p.getToken(VAULT_SCOPE).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ReauthRequiredError);
    expect(err).toMatchObject({ reason: "conditional-access", claims });
  });

  it("asks for sign-in again when the user's token can't be refreshed", async () => {
    const { c, clock } = client({
      silentError: { name: "InteractionRequiredAuthError", errorCode: "no_tokens_found" },
    });
    const p = new OboTokenProvider(c, account, API, clock);
    await expect(p.getToken(VAULT_SCOPE)).rejects.toMatchObject({ reason: "expired" });
  });

  it("passes other errors through", async () => {
    const boom = new Error("network down");
    const { c, clock } = client({ oboError: boom });
    const p = new OboTokenProvider(c, account, API, clock);
    await expect(p.getToken(VAULT_SCOPE)).rejects.toBe(boom);
  });

  it("doesn't put tokens in error messages", async () => {
    const { c, clock } = client({ oboError: { errorCode: "consent_required" } });
    const p = new OboTokenProvider(c, account, API, clock);
    const err = (await p.getToken(VAULT_SCOPE).catch((e: unknown) => e)) as Error;
    expect(err.message).not.toContain("user-token");
  });
});

describe("oboCredential", () => {
  it("only issues tokens for its own resource", async () => {
    const { c, clock } = client();
    const cred = oboCredential(new OboTokenProvider(c, account, API, clock), VAULT_SCOPE);
    await expect(cred.getToken(VAULT_SCOPE)).resolves.toMatchObject({ token: `${VAULT_SCOPE}#1` });
    await expect(cred.getToken([VAULT_SCOPE])).resolves.toBeTruthy();
    await expect(cred.getToken(ARM_SCOPE)).rejects.toThrow(/only issues tokens/);
  });
});

describe("classifyAuthError", () => {
  it("ignores unrelated errors", () => {
    expect(classifyAuthError(new Error("socket hang up"))).toBeUndefined();
    expect(classifyAuthError(undefined)).toBeUndefined();
  });
});
