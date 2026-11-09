/**
 * Only allow a path on this site as a place to send someone after sign-in.
 * Anything else (another host, a protocol, odd slashes) falls back to the home page.
 */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value || typeof value !== "string") return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  if (/[\u0000-\u001f]/.test(value)) return "/";
  try {
    const url = new URL(value, "http://keyring.invalid");
    if (url.origin !== "http://keyring.invalid") return "/";
    if (url.pathname.startsWith("/auth/")) return "/";
    return url.pathname + url.search;
  } catch {
    return "/";
  }
}

export function signInPath(returnTo: string, reason?: "expired"): string {
  const params = new URLSearchParams();
  if (returnTo && returnTo !== "/") params.set("returnTo", returnTo);
  if (reason) params.set("reason", reason);
  const qs = params.toString();
  return qs ? `/sign-in?${qs}` : "/sign-in";
}
