import { expiryState } from "./expiry";

export type FilterableSecret = {
  name: string;
  enabled: boolean;
  expiresOn?: string;
  tags: Record<string, string>;
};

export type SecretFilter = {
  q?: string;
  tag?: string;
  /** Expired or expiring within 30 days. */
  expiring?: boolean;
  disabled?: boolean;
};

export function filterSecrets<T extends FilterableSecret>(
  items: T[],
  f: SecretFilter,
  now = Date.now(),
): T[] {
  const q = f.q?.trim().toLowerCase();
  const tag = f.tag?.trim().toLowerCase();
  return items.filter((s) => {
    if (q && !s.name.toLowerCase().includes(q)) return false;
    if (tag) {
      const [key, value] = tag.split("=", 2);
      const hit = Object.entries(s.tags).some(
        ([k, v]) => k.toLowerCase() === key && (value === undefined || v.toLowerCase() === value),
      );
      if (!hit) return false;
    }
    if (f.expiring) {
      const st = expiryState(s.expiresOn, now);
      if (st !== "expired" && st !== "soon") return false;
    }
    if (f.disabled && s.enabled) return false;
    return true;
  });
}
