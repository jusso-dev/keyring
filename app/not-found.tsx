import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center gap-4 px-6 py-24">
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="text-zinc-700">That page doesn&apos;t exist, or it&apos;s moved.</p>
      <Link href="/" className="w-fit font-medium text-blue-700 underline">
        Go home
      </Link>
    </main>
  );
}
