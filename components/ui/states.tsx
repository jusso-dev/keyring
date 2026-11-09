import type { ReactNode } from "react";
import type { FriendlyError } from "@/lib/errors";

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-3 py-8 text-zinc-700">
      <span
        aria-hidden="true"
        className="h-4 w-4 animate-spin rounded-full border-2 border-zinc-300 border-t-blue-700"
      />
      <span>{label}…</span>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-zinc-300 p-8 text-center">
      <h2 className="text-lg font-semibold">{title}</h2>
      {children ? <div className="mt-2 text-zinc-700">{children}</div> : null}
    </div>
  );
}

export function ErrorNotice({ error, action }: { error: FriendlyError; action?: ReactNode }) {
  return (
    <div role="alert" className="rounded-lg border border-red-300 bg-red-50 p-4 text-red-900">
      <h2 className="font-semibold">{error.title}</h2>
      <p className="mt-1">{error.message}</p>
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

export function ComingSoon({ title }: { title: string }) {
  return (
    <Empty title={`${title} are on the way`}>
      This part of Keyring isn&apos;t built yet. Check back soon.
    </Empty>
  );
}
