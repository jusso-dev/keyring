"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type ValueError = { title: string; message: string; reauth?: string };

export async function fetchSecretValue(
  vault: string,
  name: string,
  version?: string,
): Promise<{ value: string } | { error: ValueError }> {
  const res = await fetch(
    `/api/vaults/${encodeURIComponent(vault)}/secrets/${encodeURIComponent(name)}/value`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(version ? { version } : {}),
      cache: "no-store",
      credentials: "same-origin",
    },
  );
  const body = (await res.json().catch(() => null)) as {
    value?: string;
    error?: ValueError;
  } | null;
  if (!res.ok || !body || typeof body.value !== "string") {
    return {
      error: body?.error ?? {
        title: "Something went wrong",
        message: "We couldn't load the value.",
      },
    };
  }
  return { value: body.value };
}

/** Counts down once a second. Calls onDone at zero. */
export function useCountdown(onDone: () => void) {
  const [left, setLeft] = useState(0);
  const done = useRef(onDone);
  useEffect(() => {
    done.current = onDone;
  }, [onDone]);
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => {
      if (left === 1) done.current();
      setLeft(left - 1);
    }, 1000);
    return () => clearTimeout(t);
  }, [left]);
  const start = useCallback((seconds: number) => setLeft(seconds), []);
  const stop = useCallback(() => setLeft(0), []);
  return { left, start, stop };
}
