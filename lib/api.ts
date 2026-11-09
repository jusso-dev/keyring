import "server-only";
import { NextResponse } from "next/server";
import { getConfig } from "@/lib/config";
import { isSameOrigin } from "@/lib/auth/origin";
import { getSession } from "@/lib/auth/session";
import { ReauthRequiredError } from "@/lib/auth/obo";
import { reauthPath } from "@/lib/auth/reauth";
import { toFriendlyError, type Action, type Area } from "@/lib/errors";
import { log } from "@/lib/log";

export const NO_STORE = { "Cache-Control": "no-store, max-age=0", Pragma: "no-cache" };

export function json(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: NO_STORE });
}

export type ApiError = { error: { title: string; message: string; reauth?: string } };

/**
 * Wraps a JSON route that acts on Azure. Checks the session and origin,
 * maps errors to plain messages, and never logs request or response bodies.
 */
export async function apiRoute(
  req: Request,
  context: { area: Area; action: Action; name?: string; returnTo?: string },
  fn: () => Promise<Response>,
): Promise<Response> {
  if (!isSameOrigin(req.headers, getConfig().baseUrl)) {
    return json(
      { error: { title: "Not allowed", message: "This request came from another site." } },
      403,
    );
  }
  if (!(await getSession())) {
    return json(
      {
        error: {
          title: "Please sign in again",
          message: "Your session ended.",
          reauth: "/sign-in",
        },
      },
      401,
    );
  }
  try {
    return await fn();
  } catch (err) {
    if (err instanceof ReauthRequiredError) {
      return json(
        {
          error: {
            title: "Please sign in again",
            message: err.message,
            reauth: reauthPath(err, context.returnTo ?? "/"),
          },
        },
        401,
      );
    }
    const friendly = toFriendlyError(err, context);
    const status = (err as { statusCode?: number })?.statusCode;
    log.warn("azure call failed", {
      area: context.area,
      action: context.action,
      status,
      kind: friendly.kind,
    });
    return json(
      { error: { title: friendly.title, message: friendly.message } },
      statusFor(friendly.kind),
    );
  }
}

function statusFor(kind: string): number {
  switch (kind) {
    case "signed-out":
      return 401;
    case "forbidden":
    case "private-network":
      return 403;
    case "not-found":
      return 404;
    case "conflict":
    case "soft-deleted":
      return 409;
    case "throttled":
      return 429;
    default:
      return 502;
  }
}
