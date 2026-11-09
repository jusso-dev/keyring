"use client";

import { usePathname, useRouter } from "next/navigation";
import { useId } from "react";
import { parseVaultPath, vaultHref } from "@/lib/nav";

export type PickerVault = { name: string; subscriptionName: string };

export function VaultPicker({ vaults, last }: { vaults: PickerVault[]; last?: string }) {
  const pathname = usePathname();
  const router = useRouter();
  const id = useId();
  const { vault, section } = parseVaultPath(pathname);
  const current = vault ?? last ?? "";
  return (
    <div className="flex items-center gap-2">
      <label htmlFor={id} className="text-sm text-zinc-700">
        Vault
      </label>
      <select
        id={id}
        value={vaults.some((v) => v.name === current) ? current : ""}
        onChange={(e) => {
          if (e.target.value) router.push(vaultHref(e.target.value, section));
        }}
        className="max-w-xs rounded-md border border-zinc-300 bg-white px-2 py-1 text-sm"
      >
        <option value="">Pick a vault</option>
        {vaults.map((v) => (
          <option key={`${v.subscriptionName}/${v.name}`} value={v.name}>
            {v.name} ({v.subscriptionName})
          </option>
        ))}
      </select>
    </div>
  );
}
