import "server-only";
import { unstable_rethrow } from "next/navigation";
import { ReauthRequiredError } from "@/lib/auth/obo";
import { withReauth } from "@/lib/auth/reauth";
import { toFriendlyError, type Action, type Area, type FriendlyError } from "@/lib/errors";
import { log } from "@/lib/log";

/**
 * Runs an Azure call for a page. Re-auth and Next.js redirects still happen.
 * Everything else comes back as a friendly error for the page to show.
 */
export async function attempt<T>(
  fn: () => Promise<T>,
  context: { area: Area; action?: Action; name?: string },
): Promise<{ ok: true; value: T } | { ok: false; error: FriendlyError }> {
  try {
    return { ok: true, value: await withReauth(fn) };
  } catch (err) {
    unstable_rethrow(err);
    if (err instanceof ReauthRequiredError) throw err;
    const error = toFriendlyError(err, context);
    log.warn("azure call failed", {
      area: context.area,
      status: (err as { statusCode?: number })?.statusCode,
      kind: error.kind,
    });
    return { ok: false, error };
  }
}
