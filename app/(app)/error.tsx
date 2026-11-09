"use client";

import { Button } from "@/components/ui/button";
import { ErrorNotice } from "@/components/ui/states";

export default function AppError({ retry }: { error: unknown; retry: () => void }) {
  return (
    <main className="px-6 py-8">
      <ErrorNotice
        error={{
          kind: "unknown",
          title: "Something went wrong",
          message:
            "This page didn't load. Try again, and if it keeps happening, let your admin know.",
          retryable: true,
        }}
        action={<Button onClick={() => retry()}>Try again</Button>}
      />
    </main>
  );
}
