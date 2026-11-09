"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAV, isActive } from "@/lib/nav";

export function SideNav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Main" className="w-48 shrink-0 border-r border-zinc-200 px-3 py-4">
      <ul className="flex flex-col gap-1">
        {NAV.map((item) => {
          const active = isActive(pathname, item.href);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center justify-between rounded-md px-3 py-2 text-sm ${
                  active
                    ? "bg-blue-50 font-semibold text-blue-800"
                    : "text-zinc-800 hover:bg-zinc-100"
                }`}
              >
                {item.label}
                {!item.ready ? <span className="text-xs text-zinc-600">Soon</span> : null}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
