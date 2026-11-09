import Link from "next/link";
import { requireSession } from "@/lib/auth/session";
import { SideNav } from "@/components/side-nav";
import { UserMenu } from "@/components/user-menu";
import { ToastProvider } from "@/components/ui/toast";

export const dynamic = "force-dynamic";

export default async function AppLayout({ children, vaultPicker }: LayoutProps<"/">) {
  const session = await requireSession();
  return (
    <ToastProvider>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:rounded focus:bg-white focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <header className="flex items-center gap-6 border-b border-zinc-200 px-6 py-3">
        <Link href="/" className="text-lg font-semibold">
          Keyring
        </Link>
        <div className="flex-1">{vaultPicker}</div>
        <UserMenu name={session.user.name} />
      </header>
      <div className="flex flex-1">
        <SideNav />
        <div id="main" className="flex min-w-0 flex-1 flex-col">
          {children}
        </div>
      </div>
    </ToastProvider>
  );
}
