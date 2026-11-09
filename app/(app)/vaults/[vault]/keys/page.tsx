import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { loadVault } from "@/lib/azure/vault-page";

export default async function KeysPage({ params }: PageProps<"/vaults/[vault]/keys">) {
  const vault = await loadVault((await params).vault);
  return (
    <Page title="Keys" description={vault.name}>
      <ComingSoon title="Keys" />
    </Page>
  );
}
