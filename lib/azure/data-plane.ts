import "server-only";
import { userCredentials } from "@/lib/auth/azure-credential";
import { secretClient } from "./secrets";
import type { Vault } from "./vaults";

const VAULT_HOST_SUFFIXES = [
  ".vault.azure.net",
  ".vault.azure.cn",
  ".vault.usgovcloudapi.net",
  ".vault.microsoftazure.de",
];

/** Only send Key Vault tokens to a real Key Vault host over https. */
export function isKeyVaultUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    return u.protocol === "https:" && VAULT_HOST_SUFFIXES.some((s) => u.hostname.endsWith(s));
  } catch {
    return false;
  }
}

function checkedUri(vault: Vault): string {
  if (!isKeyVaultUri(vault.vaultUri)) throw new Error("Vault address isn't a Key Vault host.");
  return vault.vaultUri;
}

/** A SecretClient for this vault, acting as the signed-in person. Make one per request. */
export async function secretsFor(vault: Vault) {
  const { keyVault } = await userCredentials();
  return secretClient(checkedUri(vault), keyVault);
}
