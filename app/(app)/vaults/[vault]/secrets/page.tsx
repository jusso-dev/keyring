import { Page } from "@/components/page";
import { SecretTable } from "@/components/secrets/secret-table";
import { Empty, ErrorNotice } from "@/components/ui/states";
import { secretsFor } from "@/lib/azure/data-plane";
import { attempt } from "@/lib/azure/safe";
import { listSecrets } from "@/lib/azure/secrets";
import { loadVault } from "@/lib/azure/vault-page";
import { vaultHref } from "@/lib/nav";

export default async function SecretsPage({ params }: PageProps<"/vaults/[vault]/secrets">) {
  const vault = await loadVault((await params).vault);
  const result = await attempt(async () => listSecrets(await secretsFor(vault)), {
    area: "secrets",
    action: "read",
  });
  return (
    <Page title="Secrets" description={`In ${vault.name}`}>
      {!result.ok ? (
        <ErrorNotice error={result.error} />
      ) : result.value.items.length === 0 ? (
        <Empty title="No secrets yet">This vault doesn&apos;t have any secrets.</Empty>
      ) : (
        <>
          {result.value.truncated ? (
            <p role="status" className="text-sm text-amber-900">
              This vault has a lot of secrets. Only the first {result.value.items.length} are shown.
            </p>
          ) : null}
          <SecretTable items={result.value.items} baseHref={vaultHref(vault.name, "secrets")} />
        </>
      )}
    </Page>
  );
}
