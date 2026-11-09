"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { clearIfUnchanged } from "@/lib/clipboard";
import { fetchSecretValue, useCountdown, type ValueError } from "./use-secret-value";

export type SecretValueProps = {
  vault: string;
  name: string;
  version?: string;
  revealSeconds: number;
  clipboardSeconds: number;
};

/**
 * Value is hidden by default and only fetched on Reveal or Copy. A revealed
 * value hides again after a timeout and when the component unmounts (for
 * example on navigation). Copied values are cleared from the clipboard.
 * Give it a key of vault/name/version so it starts fresh for each item.
 */
export function SecretValue({
  vault,
  name,
  version,
  revealSeconds,
  clipboardSeconds,
}: SecretValueProps) {
  const [value, setValue] = useState<string | null>(null);
  const [busy, setBusy] = useState<"reveal" | "copy" | null>(null);
  const [error, setError] = useState<ValueError | null>(null);
  const copied = useRef<string | null>(null);

  const hide = useCallback(() => setValue(null), []);
  const reveal = useCountdown(hide);
  const clear = useCallback(() => {
    const v = copied.current;
    copied.current = null;
    if (v !== null) void clearIfUnchanged(v);
  }, []);
  const clip = useCountdown(clear);

  // Hide on navigation away or when the tab is hidden.
  useEffect(() => {
    const onHide = () => {
      if (document.visibilityState === "hidden") setValue(null);
    };
    document.addEventListener("visibilitychange", onHide);
    return () => {
      document.removeEventListener("visibilitychange", onHide);
      setValue(null);
    };
  }, []);

  async function load(): Promise<string | null> {
    setError(null);
    const res = await fetchSecretValue(vault, name, version);
    if ("error" in res) {
      if (res.error.reauth) {
        window.location.assign(res.error.reauth);
        return null;
      }
      setError(res.error);
      return null;
    }
    return res.value;
  }

  async function onReveal() {
    if (value !== null) {
      reveal.stop();
      setValue(null);
      return;
    }
    setBusy("reveal");
    const v = await load();
    setBusy(null);
    if (v === null) return;
    setValue(v);
    reveal.start(revealSeconds);
  }

  async function onCopy() {
    setBusy("copy");
    const v = value ?? (await load());
    setBusy(null);
    if (v === null) return;
    try {
      await navigator.clipboard.writeText(v);
    } catch {
      setError({
        title: "Couldn't copy",
        message: "Your browser blocked the clipboard. Reveal the value and copy it by hand.",
      });
      return;
    }
    copied.current = v;
    clip.start(clipboardSeconds);
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <output
          aria-label="Secret value"
          aria-live="polite"
          className="min-h-9 min-w-64 flex-1 rounded-md border border-zinc-300 bg-zinc-50 px-3 py-1.5 font-mono text-sm break-all"
        >
          {value !== null
            ? value || <span className="text-zinc-600">(empty)</span>
            : "••••••••••••"}
        </output>
        <Button variant="secondary" onClick={onReveal} disabled={busy !== null}>
          {busy === "reveal" ? "Loading…" : value !== null ? "Hide" : "Reveal"}
        </Button>
        <Button variant="secondary" onClick={onCopy} disabled={busy !== null}>
          {busy === "copy" ? "Copying…" : "Copy"}
        </Button>
      </div>
      <p className="text-sm text-zinc-700" aria-live="polite">
        {value !== null && reveal.left > 0 ? `Hiding in ${reveal.left}s. ` : ""}
        {clip.left > 0 ? `Copied. Clipboard clears in ${clip.left}s.` : ""}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-red-800">
          <strong>{error.title}.</strong> {error.message}
        </p>
      ) : null}
    </div>
  );
}
