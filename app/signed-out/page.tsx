import Link from "next/link";

export default function SignedOutPage() {
  return (
    <main className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center gap-6 px-6 py-24">
      <h1 className="text-3xl font-semibold tracking-tight">You&apos;re signed out</h1>
      <p className="text-zinc-700">You can close this tab, or sign in again.</p>
      <Link href="/sign-in" className="w-fit font-medium text-blue-700 underline">
        Sign in again
      </Link>
    </main>
  );
}
