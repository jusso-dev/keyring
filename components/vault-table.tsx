"use client";

import Link from "next/link";
import { useId, useMemo, useState } from "react";
import { vaultHref } from "@/lib/nav";
import { filterVaults } from "@/lib/vault-filter";

export type VaultRow = {
  id: string;
  name: string;
  subscriptionId: string;
  subscriptionName: string;
  resourceGroup: string;
  location: string;
  rbac: boolean;
  softDelete: boolean;
  purgeProtection: boolean;
  publicNetworkAccess: "Enabled" | "Disabled";
  tags: Record<string, string>;
};

const PAGE = 50;

function Badge({ on, yes, no }: { on: boolean; yes: string; no: string }) {
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-xs font-medium ${on ? "bg-green-100 text-green-900" : "bg-zinc-100 text-zinc-800"}`}
    >
      {on ? yes : no}
    </span>
  );
}

export function VaultTable({ vaults }: { vaults: VaultRow[] }) {
  const [q, setQ] = useState("");
  const [subscription, setSubscription] = useState("");
  const [tag, setTag] = useState("");
  const [shown, setShown] = useState(PAGE);
  const ids = { q: useId(), sub: useId(), tag: useId() };

  const subscriptions = useMemo(() => {
    const m = new Map<string, string>();
    for (const v of vaults) m.set(v.subscriptionId, v.subscriptionName);
    return [...m].sort((a, b) => a[1].localeCompare(b[1]));
  }, [vaults]);
  const rows = useMemo(
    () => filterVaults(vaults, { q, subscription, tag }),
    [vaults, q, subscription, tag],
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-4">
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
              setShown(PAGE);
            }}
            placeholder="Vault or resource group"
            className="w-64 rounded-md border border-zinc-400 px-3 py-1.5"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.sub} className="text-sm font-medium">
            Subscription
          </label>
          <select
            id={ids.sub}
            value={subscription}
            onChange={(e) => setSubscription(e.target.value)}
            className="rounded-md border border-zinc-400 bg-white px-2 py-1.5"
          >
            <option value="">All subscriptions</option>
            {subscriptions.map(([id, name]) => (
              <option key={id} value={id}>
                {name}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.tag} className="text-sm font-medium">
            Tag
          </label>
          <input
            id={ids.tag}
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            placeholder="env or env=prod"
            className="w-48 rounded-md border border-zinc-400 px-3 py-1.5"
          />
        </div>
      </div>
      <p className="text-sm text-zinc-700" aria-live="polite">
        Showing {Math.min(shown, rows.length)} of {rows.length} vaults
        {rows.length !== vaults.length ? ` (${vaults.length} in total)` : ""}
      </p>
      {rows.length === 0 ? (
        <p className="text-zinc-700">No vaults match those filters.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-300">
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Name
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Subscription
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Resource group
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Location
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Access model
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Soft delete
                </th>
                <th scope="col" className="py-2 pr-4 font-semibold">
                  Purge protection
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, shown).map((v) => (
                <tr key={v.id} className="border-b border-zinc-200">
                  <td className="py-2 pr-4">
                    <Link href={vaultHref(v.name)} className="font-medium text-blue-700 underline">
                      {v.name}
                    </Link>
                    {v.publicNetworkAccess === "Disabled" ? (
                      <span className="ml-2 text-xs text-zinc-700">Private</span>
                    ) : null}
                  </td>
                  <td className="py-2 pr-4">{v.subscriptionName}</td>
                  <td className="py-2 pr-4">{v.resourceGroup}</td>
                  <td className="py-2 pr-4">{v.location}</td>
                  <td className="py-2 pr-4">{v.rbac ? "Azure RBAC" : "Access policies"}</td>
                  <td className="py-2 pr-4">
                    <Badge on={v.softDelete} yes="On" no="Off" />
                  </td>
                  <td className="py-2 pr-4">
                    <Badge on={v.purgeProtection} yes="On" no="Off" />
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
