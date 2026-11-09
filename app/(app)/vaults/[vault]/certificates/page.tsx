import { Page } from "@/components/page";
import { ComingSoon } from "@/components/ui/states";
import { loadVault } from "@/lib/azure/vault-page";

export default async function CertificatesPage({
  params,
}: PageProps<"/vaults/[vault]/certificates">) {
  const vault = await loadVault((await params).vault);
  return (
    <Page title="Certificates" description={vault.name}>
      <ComingSoon title="Certificates" />
    </Page>
  );
}
