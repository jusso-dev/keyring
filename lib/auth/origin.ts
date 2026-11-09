/** True if a state-changing request came from this site. Used as a CSRF check. */
export function isSameOrigin(headers: Headers, baseUrl: string): boolean {
  const expected = new URL(baseUrl).origin;
  const origin = headers.get("origin");
  if (origin) return origin === expected;
  const referer = headers.get("referer");
  if (referer) {
    try {
      return new URL(referer).origin === expected;
    } catch {
      return false;
    }
  }
  return false;
}
