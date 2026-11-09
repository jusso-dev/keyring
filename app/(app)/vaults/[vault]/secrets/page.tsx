import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { loadVault } from "@/lib/azure/vault-page";

export default async function SecretsPage({ params }: PageProps<"/vaults/[vault]/secrets">) {
  const vault = await loadVault((await params).vault);
  return (
    <Page title="Secrets" description={vault.name}>
      <ComingSoon title="Secrets" />
    </Page>
  );
}
