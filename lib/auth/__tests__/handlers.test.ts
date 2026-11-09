import { NextRequest } from "next/server";
import type { ConfidentialClientApplication } from "@azure/msal-node";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Config } from "@/lib/config";
import { AUTH_FLOW_COOKIE, SESSION_COOKIE, signId, verifySignedId } from "../cookie";
import { handleCallback, handleLogin, handleSignOut } from "../handlers";
import { stores } from "../session-store";

const config: Config = {
  tenantId: "tenant-id",
  clientId: "client-id",
  clientSecret: "client-secret",
  baseUrl: "https://keyring.example.com",
  sessionSecret: "s".repeat(32),
  apiScope: "api://client-id/access_as_user",
  allowPurge: false,
};

function fakeMsal() {
  const msal = {
    getAuthCodeUrl: vi.fn(async (req: { state: string }) => {
      return `https://login.example/authorize?state=${req.state}`;
    }),
    acquireTokenByCode: vi.fn(async () => ({
      accessToken: "user-access-token",
      account: {
        homeAccountId: "home",
        localAccountId: "oid-1",
        environment: "login.microsoftonline.com",
        tenantId: "tenant-id",
        username: "alex@example.com",
        name: "Alex",
      },
      idTokenClaims: { name: "Alex Smith", oid: "oid-1" },
    })),
  };
  return msal as unknown as ConfidentialClientApplication & typeof msal;
}

function cookieValue(res: Response, name: string): string | undefined {
  const all = res.headers.getSetCookie();
  const match = all.find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split(";")[0].slice(name.length + 1)) : undefined;
}

async function startLogin(msal: ReturnType<typeof fakeMsal>, returnTo = "/vaults?q=1") {
  const req = new NextRequest(
    `${config.baseUrl}/auth/login?returnTo=${encodeURIComponent(returnTo)}`,
  );
  const res = await handleLogin(req, config, () => msal);
  const location = new URL(res.headers.get("location")!);
  return {
    res,
    state: location.searchParams.get("state")!,
    flowCookie: cookieValue(res, AUTH_FLOW_COOKIE)!,
  };
}

beforeEach(() => {
  const s = stores();
  for (const store of [s.sessions, s.flows]) {
    (store as unknown as { entries: Map<string, unknown> }).entries.clear();
  }
});

describe("login", () => {
  it("uses PKCE and sets a flow cookie", async () => {
    const msal = fakeMsal();
    const { res, flowCookie } = await startLogin(msal);
    expect(res.status).toBe(307);
    const arg = msal.getAuthCodeUrl.mock.calls[0][0] as unknown as Record<string, unknown>;
    expect(arg.codeChallengeMethod).toBe("S256");
    expect(arg.codeChallenge).toBeTruthy();
    expect(arg.redirectUri).toBe("https://keyring.example.com/auth/callback");
    expect(verifySignedId(flowCookie, config.sessionSecret)).toBeTruthy();
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});

describe("callback", () => {
  it("creates a session and returns the user to the page they asked for", async () => {
    const msal = fakeMsal();
    const { state, flowCookie } = await startLogin(msal);
    const req = new NextRequest(`${config.baseUrl}/auth/callback?code=abc&state=${state}`, {
      headers: { cookie: `${AUTH_FLOW_COOKIE}=${encodeURIComponent(flowCookie)}` },
    });
    const res = await handleCallback(req, config, () => msal);
    expect(res.headers.get("location")).toBe("https://keyring.example.com/vaults?q=1");
    const sessionCookie = cookieValue(res, SESSION_COOKIE)!;
    const id = verifySignedId(sessionCookie, config.sessionSecret)!;
    expect(stores().sessions.get(id)?.user).toMatchObject({ name: "Alex Smith", oid: "oid-1" });
    const setCookie = res.headers.getSetCookie().find((c) => c.startsWith(SESSION_COOKIE))!;
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/SameSite=lax/i);
    // Tokens never go to the browser.
    expect(res.headers.getSetCookie().join(";")).not.toContain("user-access-token");
    const call = msal.acquireTokenByCode.mock.calls[0] as unknown as [{ codeVerifier: string }];
    expect(call[0].codeVerifier).toBeTruthy();
  });

  it("rejects a mismatched state", async () => {
    const msal = fakeMsal();
    const { flowCookie } = await startLogin(msal);
    const req = new NextRequest(`${config.baseUrl}/auth/callback?code=abc&state=wrong`, {
      headers: { cookie: `${AUTH_FLOW_COOKIE}=${encodeURIComponent(flowCookie)}` },
    });
    const res = await handleCallback(req, config, () => msal);
    expect(res.headers.get("location")).toBe("https://keyring.example.com/sign-in?error=state");
    expect(cookieValue(res, SESSION_COOKIE)).toBeUndefined();
    expect(msal.acquireTokenByCode).not.toHaveBeenCalled();
  });

  it("can't replay a flow", async () => {
    const msal = fakeMsal();
    const { state, flowCookie } = await startLogin(msal);
    const make = () =>
      new NextRequest(`${config.baseUrl}/auth/callback?code=abc&state=${state}`, {
        headers: { cookie: `${AUTH_FLOW_COOKIE}=${encodeURIComponent(flowCookie)}` },
      });
    await handleCallback(make(), config, () => msal);
    const second = await handleCallback(make(), config, () => msal);
    expect(second.headers.get("location")).toContain("error=state");
  });

  it("maps a cancelled sign-in", async () => {
    const req = new NextRequest(`${config.baseUrl}/auth/callback?error=access_denied`);
    const res = await handleCallback(req, config, fakeMsal);
    expect(res.headers.get("location")).toContain("error=cancelled");
  });
});

describe("sign-out", () => {
  it("clears the session and sends the user to Entra's sign-out", async () => {
    stores().sessions.set("sid", {} as never);
    const req = new NextRequest(`${config.baseUrl}/auth/sign-out`, {
      method: "POST",
      headers: {
        origin: config.baseUrl,
        cookie: `${SESSION_COOKIE}=${encodeURIComponent(signId("sid", config.sessionSecret))}`,
      },
    });
    const res = await handleSignOut(req, config);
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toMatch(
      /^https:\/\/login\.microsoftonline\.com\/tenant-id\/oauth2\/v2\.0\/logout\?post_logout_redirect_uri=/,
    );
    expect(stores().sessions.get("sid")).toBeUndefined();
    expect(res.headers.getSetCookie().find((c) => c.startsWith(SESSION_COOKIE))).toMatch(
      /Max-Age=0/i,
    );
  });

  it("refuses cross-site sign-out", async () => {
    const req = new NextRequest(`${config.baseUrl}/auth/sign-out`, {
      method: "POST",
      headers: { origin: "https://evil.example" },
    });
    expect((await handleSignOut(req, config)).status).toBe(403);
  });
});
