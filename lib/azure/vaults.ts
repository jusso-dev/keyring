import "server-only";
import { ResourceGraphClient } from "@azure/arm-resourcegraph";
import type { TokenCredential } from "@azure/core-auth";
export { filterVaults } from "@/lib/vault-filter";

export type Vault = {
  id: string;
  name: string;
  resourceGroup: string;
  subscriptionId: string;
  subscriptionName: string;
  location: string;
  vaultUri: string;
  rbac: boolean;
  softDelete: boolean;
  purgeProtection: boolean;
  publicNetworkAccess: "Enabled" | "Disabled";
  tags: Record<string, string>;
};

/** Resource Graph allows up to 1000 rows per page. */
export const PAGE_SIZE = 1000;
/** A hard stop so a runaway loop can't hammer Resource Graph. */
export const MAX_PAGES = 50;

/**
 * The query is fixed text. Nothing from the user goes into it, so there's no
 * way to inject KQL. Filtering happens in the app after the results come back.
 */
export const VAULTS_QUERY = `resources
| where type =~ 'microsoft.keyvault/vaults'
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
  ) on subscriptionId
| project id, name, resourceGroup, subscriptionId, subscriptionName, location, tags,
    vaultUri = tostring(properties.vaultUri),
    enableRbacAuthorization = tobool(properties.enableRbacAuthorization),
    enableSoftDelete = tobool(properties.enableSoftDelete),
    enablePurgeProtection = tobool(properties.enablePurgeProtection),
    publicNetworkAccess = tostring(properties.publicNetworkAccess)
| order by name asc`;

export function buildVaultQuery(skipToken?: string) {
  return {
    query: VAULTS_QUERY,
    options: {
      top: PAGE_SIZE,
      resultFormat: "objectArray" as const,
      ...(skipToken ? { skipToken } : {}),
    },
  };
}

type Row = Record<string, unknown>;

function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

export function mapVaultRow(row: Row): Vault {
  const name = str(row.name);
  const tags: Record<string, string> = {};
  if (row.tags && typeof row.tags === "object") {
    for (const [k, v] of Object.entries(row.tags as Row)) tags[k] = String(v ?? "");
  }
  return {
    id: str(row.id),
    name,
    resourceGroup: str(row.resourceGroup),
    subscriptionId: str(row.subscriptionId),
    subscriptionName: str(row.subscriptionName) || str(row.subscriptionId),
    location: str(row.location),
    vaultUri: str(row.vaultUri) || `https://${name}.vault.azure.net/`,
    rbac: row.enableRbacAuthorization === true,
    // Soft delete is on for every vault created since 2020 and can't be turned off.
    softDelete: row.enableSoftDelete !== false,
    purgeProtection: row.enablePurgeProtection === true,
    publicNetworkAccess:
      str(row.publicNetworkAccess).toLowerCase() === "disabled" ? "Disabled" : "Enabled",
    tags,
  };
}

export type ResourceGraphLike = Pick<ResourceGraphClient, "resources">;

/** Every vault the signed-in person can see, across all their subscriptions. */
export async function listVaults(client: ResourceGraphLike): Promise<Vault[]> {
  const vaults: Vault[] = [];
  let skipToken: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await client.resources(buildVaultQuery(skipToken));
    const rows: Row[] = Array.isArray(res.data) ? res.data : [];
    for (const row of rows) vaults.push(mapVaultRow(row));
    skipToken = res.skipToken;
    if (!skipToken) break;
  }
  return vaults;
}

export function resourceGraphClient(credential: TokenCredential): ResourceGraphClient {
  return new ResourceGraphClient(credential);
}

export function subscriptionsOf(vaults: Vault[]): { id: string; name: string }[] {
  const seen = new Map<string, string>();
  for (const v of vaults) seen.set(v.subscriptionId, v.subscriptionName);
  return [...seen].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));
}

/** Key Vault names are 3 to 24 characters: letters, digits and hyphens. */
export function isVaultName(name: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$/.test(name) && !name.includes("--");
}
