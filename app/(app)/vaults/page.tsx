import { Page } from "@/components/page";
import { Empty, ErrorNotice } from "@/components/ui/states";
import { VaultTable } from "@/components/vault-table";
import { getVaults } from "@/lib/azure/vault-context";
import { toFriendlyError } from "@/lib/errors";

export default async function VaultsPage() {
  let vaults;
  try {
    vaults = await getVaults();
  } catch (err) {
    if (err && typeof err === "object" && "digest" in err) throw err;
    return (
      <Page title="Vaults">
        <ErrorNotice error={toFriendlyError(err, { area: "vaults" })} />
      </Page>
    );
  }
  return (
    <Page title="Vaults" description="Every Key Vault you can see, across all your subscriptions.">
      {vaults.length === 0 ? (
        <Empty title="No vaults to show">
          You can only see vaults in subscriptions where you have at least the Reader role. If you
          expected some here, ask your Azure admin to give you access.
        </Empty>
      ) : (
        <VaultTable vaults={vaults} />
      )}
    </Page>
  );
}
