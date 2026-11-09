import Link from "next/link";
import { requireSession } from "@/lib/auth/session";
import { UserMenu } from "@/components/user-menu";

export const dynamic = "force-dynamic";

export default async function AppLayout({ children }: LayoutProps<"/">) {
  const session = await requireSession();
  return (
    <>
      <header className="flex items-center justify-between border-b border-zinc-200 px-6 py-3">
        <Link href="/" className="text-lg font-semibold">
          Keyring
        </Link>
        <UserMenu name={session.user.name} />
      </header>
      {children}
    </>
  );
}
