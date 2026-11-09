export type NavItem = { href: string; label: string; ready: boolean };

export const NAV: NavItem[] = [
  { href: "/vaults", label: "Vaults", ready: false },
  { href: "/secrets", label: "Secrets", ready: false },
  { href: "/certificates", label: "Certificates", ready: false },
  { href: "/keys", label: "Keys", ready: false },
  { href: "/expiry", label: "Expiry", ready: false },
  { href: "/generator", label: "Generator", ready: false },
  { href: "/audit", label: "Audit", ready: false },
];

export function isActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}
