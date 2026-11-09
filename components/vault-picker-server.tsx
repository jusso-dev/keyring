import { requireSession } from "@/lib/auth/session";
import { getVaults, lastVault } from "@/lib/azure/vault-context";
import { VaultPicker } from "./vault-picker";
import { ReauthRequiredError } from "@/lib/auth/obo";

export async function VaultPickerServer() {
  const session = await requireSession();
  let vaults;
  try {
    vaults = await getVaults();
  } catch (err) {
    // The vaults page shows the full error. The picker just stays out of the way.
    if (err instanceof ReauthRequiredError) throw err;
    if (err && typeof err === "object" && "digest" in err) throw err;
    return null;
  }
  return (
    <VaultPicker
      vaults={vaults.map((v) => ({ name: v.name, subscriptionName: v.subscriptionName }))}
      last={lastVault(session)}
    />
  );
}
