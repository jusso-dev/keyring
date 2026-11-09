import "server-only";
import type { TokenCredential } from "@azure/core-auth";
import { SecretClient, type SecretProperties } from "@azure/keyvault-secrets";

/**
 * Secret metadata safe to send to the browser. Never holds a value. Dates are
 * ISO strings so they cross the server/client boundary cleanly.
 */
export type SecretItem = {
  name: string;
  version: string;
  enabled: boolean;
  contentType: string;
  createdOn?: string;
  updatedOn?: string;
  expiresOn?: string;
  notBefore?: string;
  tags: Record<string, string>;
  managed: boolean;
};

/** Stop listing after this many, so one huge vault can't stall the server. */
export const MAX_SECRETS = 25_000;

export function secretClient(vaultUri: string, credential: TokenCredential): SecretClient {
  return new SecretClient(vaultUri, credential);
}

const iso = (d?: Date) => (d ? d.toISOString() : undefined);

export function toSecretItem(p: SecretProperties): SecretItem {
  return {
    name: p.name,
    version: p.version ?? "",
    enabled: p.enabled !== false,
    contentType: p.contentType ?? "",
    createdOn: iso(p.createdOn),
    updatedOn: iso(p.updatedOn),
    expiresOn: iso(p.expiresOn),
    notBefore: iso(p.notBefore),
    tags: { ...(p.tags ?? {}) },
    managed: p.managed === true,
  };
}

export type SecretsReader = Pick<SecretClient, "listPropertiesOfSecrets">;

/** Every secret's properties in the vault. Reads no values. */
export async function listSecrets(
  client: SecretsReader,
): Promise<{ items: SecretItem[]; truncated: boolean }> {
  const items: SecretItem[] = [];
  for await (const page of client.listPropertiesOfSecrets().byPage({ maxPageSize: 25 })) {
    for (const p of page) {
      // Certificate-backed secrets are managed by Key Vault. They show under Certificates.
      if (p.managed) continue;
      items.push(toSecretItem(p));
      if (items.length >= MAX_SECRETS) return { items: sortByName(items), truncated: true };
    }
  }
  return { items: sortByName(items), truncated: false };
}

function sortByName(items: SecretItem[]) {
  return items.sort((a, b) => a.name.localeCompare(b.name));
}

/** Key Vault object names: 1 to 127 letters, digits and hyphens. */
export const SECRET_NAME_RE = /^[0-9a-zA-Z-]{1,127}$/;

export function isSecretName(name: string): boolean {
  return SECRET_NAME_RE.test(name);
}

/** Version ids are 32 hex characters. */
export function isVersionId(v: string): boolean {
  return /^[0-9a-f]{32}$/i.test(v);
}

export type VersionsReader = Pick<SecretClient, "listPropertiesOfSecretVersions">;

/** Every version's properties, newest first. Reads no values. */
export async function listSecretVersions(
  client: VersionsReader,
  name: string,
): Promise<SecretItem[]> {
  const items: SecretItem[] = [];
  for await (const p of client.listPropertiesOfSecretVersions(name)) items.push(toSecretItem(p));
  return items.sort((a, b) => (b.createdOn ?? "").localeCompare(a.createdOn ?? ""));
}

/**
 * Properties of the current version. Key Vault's current version is the most
 * recently created one. Uses the versions list, which never carries values.
 * Returns undefined if the secret doesn't exist.
 */
export async function getSecretProperties(
  client: VersionsReader,
  name: string,
): Promise<SecretItem | undefined> {
  const versions = await listSecretVersions(client, name);
  return versions[0];
}
