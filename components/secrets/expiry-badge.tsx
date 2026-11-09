import { EXPIRY_LABEL, expiryState } from "@/lib/expiry";

const STYLE = {
  expired: "bg-red-100 text-red-900",
  soon: "bg-amber-100 text-amber-900",
  upcoming: "bg-yellow-50 text-yellow-900",
  ok: "",
  none: "",
};

export function ExpiryBadge({ expiresOn, now }: { expiresOn?: string; now?: number }) {
  const state = expiryState(expiresOn, now);
  if (!EXPIRY_LABEL[state]) return null;
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${STYLE[state]}`}>
      {EXPIRY_LABEL[state]}
    </span>
  );
}

export function DisabledBadge() {
  return (
    <span className="rounded bg-zinc-200 px-1.5 py-0.5 text-xs font-medium text-zinc-900">
      Disabled
    </span>
  );
}
