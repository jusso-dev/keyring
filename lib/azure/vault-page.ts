import "server-only";
import { notFound } from "next/navigation";
import { requireSession } from "@/lib/auth/session";
import { findVault, rememberVault } from "./vault-context";
import type { Vault } from "./vaults";

/**
 * Looks up the vault named in the URL. Seeing a vault in Resource Graph
 * doesn't mean the person can read its contents. Data-plane pages still
 * handle a 403 when they load.
 */
export async function loadVault(rawName: string): Promise<Vault> {
  const session = await requireSession();
  const vault = await findVault(decodeURIComponent(rawName));
  if (!vault) notFound();
  rememberVault(session, vault.name);
  return vault;
}
