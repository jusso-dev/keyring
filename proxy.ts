import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE } from "@/lib/auth/cookie";
import { signInPath } from "@/lib/auth/return-to";
import { PATH_HEADER, isPublicPath } from "@/lib/auth/public-paths";

/**
 * A quick first check only. Pages, actions and routes still call
 * requireSession(), which is the real check.
 */
export function proxy(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set(PATH_HEADER, pathname + search);
  if (!isPublicPath(pathname) && !req.cookies.get(SESSION_COOKIE)?.value) {
    return NextResponse.redirect(new URL(signInPath(pathname + search), req.url));
  }
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
