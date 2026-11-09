/** Shared by the server and the vault table. No server-only imports here. */
export type FilterableVault = {
  name: string;
  resourceGroup: string;
  subscriptionId: string;
  tags: Record<string, string>;
};

export type VaultFilter = { q?: string; subscription?: string; tag?: string };

/** Filters by name or resource group, subscription and tag. Tag can be "key" or "key=value". */
export function filterVaults<T extends FilterableVault>(vaults: T[], f: VaultFilter): T[] {
  const q = f.q?.trim().toLowerCase();
  const tag = f.tag?.trim().toLowerCase();
  return vaults.filter((v) => {
    if (q && !v.name.toLowerCase().includes(q) && !v.resourceGroup.toLowerCase().includes(q)) {
      return false;
    }
    if (f.subscription && v.subscriptionId !== f.subscription) return false;
    if (tag) {
      const [key, value] = tag.split("=", 2);
      const hit = Object.entries(v.tags).some(
        ([k, val]) =>
          k.toLowerCase() === key && (value === undefined || val.toLowerCase() === value),
      );
      if (!hit) return false;
    }
    return true;
  });
}
