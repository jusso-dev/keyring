/** Expiry buckets shared by secrets, certificates, keys and the dashboard. */
export type ExpiryState = "expired" | "soon" | "upcoming" | "ok" | "none";

export const DAY_MS = 24 * 60 * 60 * 1000;
export const SOON_DAYS = 30;
export const UPCOMING_DAYS = 90;

export function expiryState(
  expiresOn: Date | string | undefined | null,
  now = Date.now(),
): ExpiryState {
  if (!expiresOn) return "none";
  const t = typeof expiresOn === "string" ? Date.parse(expiresOn) : expiresOn.getTime();
  if (Number.isNaN(t)) return "none";
  if (t <= now) return "expired";
  if (t - now <= SOON_DAYS * DAY_MS) return "soon";
  if (t - now <= UPCOMING_DAYS * DAY_MS) return "upcoming";
  return "ok";
}

export const EXPIRY_LABEL: Record<ExpiryState, string> = {
  expired: "Expired",
  soon: "Expires soon",
  upcoming: "Expires in 90 days",
  ok: "",
  none: "",
};
