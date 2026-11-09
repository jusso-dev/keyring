import { redirect } from "next/navigation";
import { vaultHref } from "@/lib/nav";

export default async function VaultPage({ params }: PageProps<"/vaults/[vault]">) {
  const { vault } = await params;
  redirect(vaultHref(decodeURIComponent(vault)));
}
