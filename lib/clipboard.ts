/**
 * Clears the clipboard, but only if it still holds the value we put there.
 * If the browser won't let us read the clipboard, we clear it anyway, since
 * leaving a secret behind is worse than wiping something the person copied later.
 */
export async function clearIfUnchanged(
  value: string,
  clipboard: Clipboard | undefined = globalThis.navigator?.clipboard,
) {
  if (!clipboard) return;
  try {
    const current = await clipboard.readText();
    if (current !== value) return;
  } catch {
    // Reading needs permission in some browsers. Fall through and clear.
  }
  try {
    await clipboard.writeText("");
  } catch {
    // Nothing more we can do.
  }
}
