import Link from "next/link";
import { reauthMessage, type ReauthReason } from "@/lib/auth/obo";
import { safeReturnTo } from "@/lib/auth/return-to";

export const dynamic = "force-dynamic";

const REASONS: ReauthReason[] = ["consent", "conditional-access", "expired"];

export default async function ReauthPage({ searchParams }: PageProps<"/reauth">) {
  const sp = await searchParams;
  const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
  const reasonParam = first(sp.reason);
  const reason = REASONS.find((r) => r === reasonParam) ?? "expired";
  const returnTo = safeReturnTo(first(sp.returnTo));
  const params = new URLSearchParams();
  if (returnTo !== "/") params.set("returnTo", returnTo);
  const claims = first(sp.claims);
  if (claims) params.set("claims", claims);
  const qs = params.toString();
  return (
    <main className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center gap-6 px-6 py-24">
      <h1 className="text-3xl font-semibold tracking-tight">
        {reason === "consent" ? "Keyring needs approval" : "Please sign in again"}
      </h1>
      <p className="text-zinc-700">{reauthMessage(reason)}</p>
      {reason === "consent" ? (
        <p className="text-sm text-zinc-700">
          Your admin needs to grant the delegated permissions for Azure Key Vault and Azure Service
          Management on the Keyring app registration.
        </p>
      ) : null}
      <div className="flex gap-4">
        <a
          href={`/auth/login${qs ? `?${qs}` : ""}`}
          className="inline-flex w-fit items-center rounded-md bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800"
        >
          Try again
        </a>
        <Link href="/" className="inline-flex items-center font-medium text-blue-700 underline">
          Go home
        </Link>
      </div>
    </main>
  );
}
