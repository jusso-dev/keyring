import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth/session";
import { lastVault } from "@/lib/azure/vault-context";
import { vaultHref } from "@/lib/nav";

/** Certificates live under a vault. Go to the last one picked, or the vault list. */
export default async function CertificatesRedirect() {
  const last = lastVault(await requireSession());
  redirect(last ? vaultHref(last, "certificates") : "/vaults");
}
