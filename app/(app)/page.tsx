import { requireSession } from "@/lib/auth/session";

export default async function Home() {
  const { user } = await requireSession();
  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-4 px-6 py-12">
      <h1 className="text-3xl font-semibold tracking-tight">Hi, {user.name}</h1>
      <p className="text-lg text-zinc-700">
        Find a vault, look up a secret, add a certificate or rotate a key. Everything you do here
        runs as you, so you see what Azure lets you see.
      </p>
    </main>
  );
}
