import "server-only";
import { NextResponse, type NextRequest } from "next/server";
import type { Config } from "@/lib/config";
import { log } from "@/lib/log";
import { AUTH_FLOW_COOKIE, SESSION_COOKIE, cookieOptions, signId, verifySignedId } from "./cookie";
import { beginSignIn, completeSignIn, SignInError, type MsalFactory } from "./flow";
import { endSessionUrl } from "./msal";
import { isSameOrigin } from "./origin";
import { AUTH_FLOW_MS, SESSION_ABSOLUTE_MS, stores } from "./session-store";

function noStore(res: NextResponse) {
  res.headers.set("Cache-Control", "no-store");
  return res;
}

export async function handleLogin(req: NextRequest, config: Config, makeMsal: MsalFactory) {
  const msal = makeMsal(config);
  const { url, flowId, flow } = await beginSignIn(
    config,
    msal,
    req.nextUrl.searchParams.get("returnTo"),
  );
  stores().flows.set(flowId, flow);
  const res = NextResponse.redirect(url);
  res.cookies.set(
    AUTH_FLOW_COOKIE,
    signId(flowId, config.sessionSecret),
    cookieOptions(config.baseUrl, AUTH_FLOW_MS / 1000),
  );
  return noStore(res);
}

export async function handleCallback(req: NextRequest, config: Config, makeMsal: MsalFactory) {
  const q = req.nextUrl.searchParams;
  const flowId = verifySignedId(req.cookies.get(AUTH_FLOW_COOKIE)?.value, config.sessionSecret);
  const flow = flowId ? stores().flows.take(flowId) : undefined;
  let target: string;
  let sessionCookie: string | undefined;
  try {
    const session = await completeSignIn(config, makeMsal(config), flow, {
      code: q.get("code"),
      state: q.get("state"),
      clientInfo: q.get("client_info"),
      error: q.get("error"),
      errorDescription: q.get("error_description"),
    });
    stores().sessions.set(session.id, { ...session, prefs: {} });
    sessionCookie = signId(session.id, config.sessionSecret);
    target = `${config.baseUrl}${flow?.returnTo ?? "/"}`;
    log.info("sign-in", { oid: session.user.oid });
  } catch (err) {
    const reason = err instanceof SignInError ? err.reason : "failed";
    if (!(err instanceof SignInError)) {
      log.warn("sign-in failed", { error: err instanceof Error ? err.name : "unknown" });
    }
    target = `${config.baseUrl}/sign-in?error=${reason}`;
  }
  const res = NextResponse.redirect(target);
  res.cookies.set(AUTH_FLOW_COOKIE, "", cookieOptions(config.baseUrl, 0));
  if (sessionCookie) {
    res.cookies.set(
      SESSION_COOKIE,
      sessionCookie,
      cookieOptions(config.baseUrl, SESSION_ABSOLUTE_MS / 1000),
    );
  }
  return noStore(res);
}

export async function handleSignOut(req: NextRequest, config: Config) {
  if (!isSameOrigin(req.headers, config.baseUrl)) {
    return noStore(new NextResponse("Forbidden", { status: 403 }));
  }
  const id = verifySignedId(req.cookies.get(SESSION_COOKIE)?.value, config.sessionSecret);
  if (id) stores().sessions.delete(id);
  // 303 so the browser follows with a GET.
  const res = NextResponse.redirect(endSessionUrl(config), 303);
  res.cookies.set(SESSION_COOKIE, "", cookieOptions(config.baseUrl, 0));
  return noStore(res);
}
