import { Page } from "@/components/page";
import { Empty, ErrorNotice } from "@/components/ui/states";
import { VaultTable } from "@/components/vault-table";
import { getVaults } from "@/lib/azure/vault-context";
import { attempt } from "@/lib/azure/safe";

export default async function VaultsPage() {
  const result = await attempt(() => getVaults(), { area: "vaults" });
  if (!result.ok) {
    return (
      <Page title="Vaults">
        <ErrorNotice error={result.error} />
      </Page>
    );
  }
  const vaults = result.value;
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
