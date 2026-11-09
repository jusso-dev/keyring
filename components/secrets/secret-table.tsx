"use client";

import Link from "next/link";
import { useId, useMemo, useState } from "react";
import { formatDate } from "@/lib/format";
import { filterSecrets } from "@/lib/secret-filter";
import { DisabledBadge, ExpiryBadge } from "./expiry-badge";

export type SecretRow = {
  name: string;
  enabled: boolean;
  contentType: string;
  updatedOn?: string;
  expiresOn?: string;
  tags: Record<string, string>;
};

const PAGE = 50;

export function SecretTable({ items, baseHref }: { items: SecretRow[]; baseHref: string }) {
  const [q, setQ] = useState("");
  const [tag, setTag] = useState("");
  const [expiring, setExpiring] = useState(false);
  const [disabled, setDisabled] = useState(false);
  const [shown, setShown] = useState(PAGE);
  const ids = { q: useId(), tag: useId(), exp: useId(), dis: useId() };
  const rows = useMemo(
    () => filterSecrets(items, { q, tag, expiring, disabled }),
    [items, q, tag, expiring, disabled],
  );
  const reset = () => setShown(PAGE);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.q} className="text-sm font-medium">
            Search
          </label>
          <input
            id={ids.q}
            type="search"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              reset();
            }}
            placeholder="Secret name"
            className="w-64 rounded-md border border-zinc-400 px-3 py-1.5"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.tag} className="text-sm font-medium">
            Tag
          </label>
          <input
            id={ids.tag}
            value={tag}
            onChange={(e) => {
              setTag(e.target.value);
              reset();
            }}
            placeholder="env or env=prod"
            className="w-48 rounded-md border border-zinc-400 px-3 py-1.5"
          />
        </div>
        <label htmlFor={ids.exp} className="flex items-center gap-2 text-sm">
          <input
            id={ids.exp}
            type="checkbox"
            checked={expiring}
            onChange={(e) => setExpiring(e.target.checked)}
          />
          Expired or expiring in 30 days
        </label>
        <label htmlFor={ids.dis} className="flex items-center gap-2 text-sm">
          <input
            id={ids.dis}
            type="checkbox"
            checked={disabled}
            onChange={(e) => setDisabled(e.target.checked)}
          />
          Disabled only
        </label>
      </div>
      <p className="text-sm text-zinc-700" aria-live="polite">
        Showing {Math.min(shown, rows.length)} of {rows.length} secrets
        {rows.length !== items.length ? ` (${items.length} in total)` : ""}
      </p>
      {rows.length === 0 ? (
        <p className="text-zinc-700">No secrets match those filters.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-300">
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Name
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Status
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Content type
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Updated
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Expires
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Tags
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, shown).map((s) => (
                <tr key={s.name} className="border-b border-zinc-200">
                  <td className="py-2 pr-4">
                    <Link
                      href={`${baseHref}/${encodeURIComponent(s.name)}`}
                      className="font-medium text-blue-700 underline"
                    >
                      {s.name}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">
                    <span className="flex flex-wrap gap-1">
                      {!s.enabled ? <DisabledBadge /> : null}
                      <ExpiryBadge expiresOn={s.expiresOn} />
                      {s.enabled && !s.expiresOn ? (
                        <span className="text-zinc-700">Enabled</span>
                      ) : null}
                    </span>
                  </td>
                  <td className="py-2 pr-4">{s.contentType}</td>
                  <td className="py-2 pr-4">{formatDate(s.updatedOn)}</td>
                  <td className="py-2 pr-4">{s.expiresOn ? formatDate(s.expiresOn) : "Never"}</td>
                  <td className="py-2 pr-4">
                    {Object.entries(s.tags)
                      .map(([k, v]) => (v ? `${k}=${v}` : k))
                      .join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {shown < rows.length ? (
        <button
          type="button"
          onClick={() => setShown((n) => n + PAGE)}
          className="w-fit rounded-md border border-zinc-300 px-3 py-1.5 text-sm font-medium hover:bg-zinc-100"
        >
          Show more
        </button>
      ) : null}
    </div>
  );
}
