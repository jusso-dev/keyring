export type Section = "secrets" | "certificates" | "keys";
export type NavItem = { href: string; label: string; ready: boolean; section?: Section };

export const NAV: NavItem[] = [
  { href: "/vaults", label: "Vaults", ready: true },
  { href: "/secrets", label: "Secrets", ready: false, section: "secrets" },
  { href: "/certificates", label: "Certificates", ready: false, section: "certificates" },
  { href: "/keys", label: "Keys", ready: false, section: "keys" },
  { href: "/expiry", label: "Expiry", ready: false },
  { href: "/generator", label: "Generator", ready: false },
  { href: "/audit", label: "Audit", ready: false },
];

export const SECTIONS: Section[] = ["secrets", "certificates", "keys"];

/** The vault name and section from a path like /vaults/my-vault/secrets/db. */
export function parseVaultPath(pathname: string): { vault?: string; section?: Section } {
  const m = /^\/vaults\/([^/]+)(?:\/([^/]+))?/.exec(pathname);
  if (!m) return {};
  const vault = decodeURIComponent(m[1]);
  const section = SECTIONS.find((s) => s === m[2]);
  return { vault, section };
}

export function isActive(pathname: string, item: NavItem): boolean {
  const { vault, section } = parseVaultPath(pathname);
  if (item.section) {
    return (
      section === item.section || pathname === item.href || pathname.startsWith(`${item.href}/`)
    );
  }
  if (item.href === "/vaults") return pathname === "/vaults" || (Boolean(vault) && !section);
  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}

export function vaultHref(vault: string, section: Section = "secrets"): string {
  return `/vaults/${encodeURIComponent(vault)}/${section}`;
}
