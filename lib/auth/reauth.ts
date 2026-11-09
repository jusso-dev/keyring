import "server-only";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { ReauthRequiredError } from "./obo";
import { PATH_HEADER } from "./public-paths";
import { safeReturnTo } from "./return-to";

export function reauthPath(err: ReauthRequiredError, returnTo: string): string {
  const params = new URLSearchParams({ reason: err.reason });
  if (returnTo !== "/") params.set("returnTo", returnTo);
  if (err.claims) params.set("claims", err.claims);
  return `/reauth?${params.toString()}`;
}

/**
 * Runs an Azure call. If Entra says the person must sign in again (consent,
 * conditional access, expired refresh token), sends them to a page that
 * explains why and lets them retry. Other errors are rethrown.
 */
export async function withReauth<T>(fn: () => Promise<T>): Promise<T> {
  let target: string | undefined;
  try {
    return await fn();
  } catch (err) {
    if (!(err instanceof ReauthRequiredError)) throw err;
    const returnTo = safeReturnTo((await headers()).get(PATH_HEADER));
    target = reauthPath(err, returnTo);
  }
  redirect(target);
}
