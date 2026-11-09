import "server-only";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { getConfig } from "@/lib/config";
import { SESSION_COOKIE, verifySignedId } from "./cookie";
import { signInPath, safeReturnTo } from "./return-to";
import { stores, type Session } from "./session-store";

import { PATH_HEADER } from "./public-paths";

/** The current session, or undefined. Does not redirect. */
export async function getSession(): Promise<Session | undefined> {
  const raw = (await cookies()).get(SESSION_COOKIE)?.value;
  const id = verifySignedId(raw, getConfig().sessionSecret);
  return id ? stores().sessions.get(id) : undefined;
}

/**
 * The current session. If there isn't one, sends the person to sign-in and
 * remembers where they were going. Call this in every page, action and route
 * that needs a user. Don't rely on layouts or the proxy alone.
 */
export async function requireSession(): Promise<Session> {
  const session = await getSession();
  if (session) return session;
  const hadCookie = Boolean((await cookies()).get(SESSION_COOKIE)?.value);
  const returnTo = safeReturnTo((await headers()).get(PATH_HEADER));
  redirect(signInPath(returnTo, hadCookie ? "expired" : undefined));
}
