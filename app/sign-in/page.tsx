import { safeReturnTo } from "@/lib/auth/return-to";
import { signInMessage } from "@/lib/auth/messages";

export const dynamic = "force-dynamic";

export default async function SignInPage({ searchParams }: PageProps<"/sign-in">) {
  const sp = await searchParams;
  const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
  const returnTo = safeReturnTo(first(sp.returnTo));
  const message = signInMessage({ reason: first(sp.reason), error: first(sp.error) });
  const href = `/auth/login${returnTo === "/" ? "" : `?returnTo=${encodeURIComponent(returnTo)}`}`;
  return (
    <main className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center gap-6 px-6 py-24">
      <h1 className="text-3xl font-semibold tracking-tight">Sign in to Keyring</h1>
      <p className="text-zinc-700">
        Use your work account. Keyring acts as you, so you&apos;ll only see the vaults and items you
        already have access to.
      </p>
      {message ? (
        <p
          role="status"
          className="rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-900"
        >
          {message}
        </p>
      ) : null}
      <a
        href={href}
        className="inline-flex w-fit items-center rounded-md bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800"
      >
        Sign in with Microsoft
      </a>
    </main>
  );
}
