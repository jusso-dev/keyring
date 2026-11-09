"use client";

import { useEffect, useId, useRef, useState } from "react";
import { Button } from "./button";

export type ConfirmDialogProps = {
  open: boolean;
  title: string;
  /** What will happen, in plain words. */
  description: string;
  /** The text the person must type to enable the button, usually the item name. */
  confirmText: string;
  actionLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
};

/**
 * A modal that only enables its destructive button once the person has typed
 * the item's name exactly. Uses the native <dialog> element for focus trapping
 * and Escape handling.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmText,
  actionLabel,
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const [typed, setTyped] = useState("");
  const inputId = useId();
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      if (typeof d.showModal === "function") d.showModal();
      else d.setAttribute("open", "");
    }
    if (!open && d.open) {
      if (typeof d.close === "function") d.close();
      else d.removeAttribute("open");
    }
  }, [open]);

  const matches = typed === confirmText;

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      aria-describedby={descId}
      onCancel={(e) => {
        e.preventDefault();
        setTyped("");
        onCancel();
      }}
      className="m-auto w-full max-w-md rounded-lg p-0 shadow-xl backdrop:bg-black/40"
    >
      {open ? (
        <form
          className="flex flex-col gap-4 p-6"
          onSubmit={(e) => {
            e.preventDefault();
            if (matches && !busy) onConfirm();
          }}
        >
          <h2 id={titleId} className="text-lg font-semibold">
            {title}
          </h2>
          <p id={descId} className="text-zinc-700">
            {description}
          </p>
          <div className="flex flex-col gap-1">
            <label htmlFor={inputId} className="text-sm font-medium">
              Type <span className="font-mono">{confirmText}</span> to confirm
            </label>
            <input
              id={inputId}
              autoFocus
              autoComplete="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              className="rounded-md border border-zinc-400 px-3 py-2 font-mono"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              onClick={() => {
                setTyped("");
                onCancel();
              }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="danger" disabled={!matches || busy}>
              {busy ? "Working…" : actionLabel}
            </Button>
          </div>
        </form>
      ) : null}
    </dialog>
  );
}
