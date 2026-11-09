import Link from "next/link";
import { notFound } from "next/navigation";
import { Page } from "@/components/page";
import { DisabledBadge, ExpiryBadge } from "@/components/secrets/expiry-badge";
import { SecretValue } from "@/components/secrets/secret-value";
import { ErrorNotice } from "@/components/ui/states";
import { getConfig } from "@/lib/config";
import { secretsFor } from "@/lib/azure/data-plane";
import { attempt } from "@/lib/azure/safe";
import { getSecretProperties, isSecretName } from "@/lib/azure/secrets";
import { loadVault } from "@/lib/azure/vault-page";
import { formatDateTime } from "@/lib/format";
import { vaultHref } from "@/lib/nav";

export default async function SecretPage({ params }: PageProps<"/vaults/[vault]/secrets/[name]">) {
  const p = await params;
  const vault = await loadVault(p.vault);
  const name = decodeURIComponent(p.name);
  if (!isSecretName(name)) notFound();
  // Properties only. getSecret would also return the value, so it's not used here.
  const result = await attempt(async () => getSecretProperties(await secretsFor(vault), name), {
    area: "secrets",
    action: "read",
    name,
  });
  const back = (
    <Link
      href={vaultHref(vault.name, "secrets")}
      className="text-sm font-medium text-blue-700 underline"
    >
      Back to secrets
    </Link>
  );
  if (!result.ok) {
    return (
      <Page title={name} description={`In ${vault.name}`} actions={back}>
        <ErrorNotice error={result.error} />
      </Page>
    );
  }
  const s = result.value;
  if (!s) notFound();
  const cfg = getConfig();
  const rows: [string, React.ReactNode][] = [
    ["Status", s.enabled ? "Enabled" : <DisabledBadge key="d" />],
    ["Content type", s.contentType || "None"],
    ["Created", formatDateTime(s.createdOn)],
    ["Updated", formatDateTime(s.updatedOn)],
    ["Activates", s.notBefore ? formatDateTime(s.notBefore) : "Straight away"],
    [
      "Expires",
      s.expiresOn ? (
        <span key="e" className="flex items-center gap-2">
          {formatDateTime(s.expiresOn)} <ExpiryBadge expiresOn={s.expiresOn} />
        </span>
      ) : (
        "Never"
      ),
    ],
    [
      "Current version",
      <span key="v" className="font-mono text-xs">
        {s.version}
      </span>,
    ],
    [
      "Tags",
      Object.keys(s.tags).length
        ? Object.entries(s.tags)
            .map(([k, v]) => (v ? `${k}=${v}` : k))
            .join(", ")
        : "None",
    ],
  ];
  return (
    <Page title={s.name} description={`In ${vault.name}`} actions={back}>
      <section aria-labelledby="value-h" className="flex flex-col gap-2">
        <h2 id="value-h" className="text-lg font-semibold">
          Value
        </h2>
        <SecretValue
          key={`${vault.name}/${s.name}`}
          vault={vault.name}
          name={s.name}
          revealSeconds={cfg.revealSeconds}
          clipboardSeconds={cfg.clipboardClearSeconds}
        />
      </section>
      <section aria-labelledby="props-h" className="flex flex-col gap-2">
        <h2 id="props-h" className="text-lg font-semibold">
          Details
        </h2>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="font-medium text-zinc-700">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      </section>
    </Page>
  );
}
