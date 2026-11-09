export const PATH_HEADER = "x-keyring-path";

export const PUBLIC_PATHS = [
  "/sign-in",
  "/signed-out",
  "/reauth",
  "/auth/login",
  "/auth/callback",
  // Sign-out checks the origin itself, so it must always reach its handler.
  "/auth/sign-out",
  "/api/health",
];

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}
