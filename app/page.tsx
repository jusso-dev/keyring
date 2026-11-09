export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col justify-center gap-4 px-6 py-24">
      <h1 className="text-3xl font-semibold tracking-tight">Keyring</h1>
      <p className="text-lg text-zinc-700">
        Find a vault, look up a secret, add a certificate or rotate a key. Everything you do here
        runs as you, so you see what Azure lets you see.
      </p>
    </main>
  );
}
