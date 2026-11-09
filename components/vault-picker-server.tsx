import { requireSession } from "@/lib/auth/session";
import { getVaults, lastVault } from "@/lib/azure/vault-context";
import { attempt } from "@/lib/azure/safe";
import { VaultPicker } from "./vault-picker";

export async function VaultPickerServer() {
  const session = await requireSession();
  // The vaults page shows the full error. The picker just stays out of the way.
  const result = await attempt(() => getVaults(), { area: "vaults" });
  if (!result.ok) return null;
  return (
    <VaultPicker
      vaults={result.value.map((v) => ({ name: v.name, subscriptionName: v.subscriptionName }))}
      last={lastVault(session)}
    />
  );
}
