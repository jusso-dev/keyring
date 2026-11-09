import { apiRoute, json } from "@/lib/api";
import { findVault } from "@/lib/azure/vault-context";
import { secretsFor } from "@/lib/azure/data-plane";
import { isSecretName, isVersionId } from "@/lib/azure/secrets";
import { vaultHref } from "@/lib/nav";

export const dynamic = "force-dynamic";

/**
 * Returns one secret value. POST only, so it's never prefetched, cached or
 * triggered by a link. The value is not logged.
 */
export async function POST(
  req: Request,
  ctx: RouteContext<"/api/vaults/[vault]/secrets/[name]/value">,
) {
  const { vault: rawVault, name: rawName } = await ctx.params;
  const vaultName = decodeURIComponent(rawVault);
  const name = decodeURIComponent(rawName);
  return apiRoute(
    req,
    {
      area: "secrets",
      action: "read",
      name,
      returnTo: `${vaultHref(vaultName)}/${encodeURIComponent(name)}`,
    },
    async () => {
      if (!isSecretName(name)) {
        return json(
          { error: { title: "Not found", message: "That isn't a valid secret name." } },
          400,
        );
      }
      const body = (await req.json().catch(() => ({}))) as { version?: unknown };
      const version = typeof body.version === "string" && body.version ? body.version : undefined;
      if (version && !isVersionId(version)) {
        return json({ error: { title: "Not found", message: "That isn't a valid version." } }, 400);
      }
      const vault = await findVault(vaultName);
      if (!vault) {
        return json(
          { error: { title: "Not found", message: "We couldn't find that vault." } },
          404,
        );
      }
      const client = await secretsFor(vault);
      const secret = await client.getSecret(name, version ? { version } : {});
      return json({ value: secret.value ?? "" });
    },
  );
}
