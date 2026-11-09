// @vitest-environment jsdom
import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecretValue } from "../secrets/secret-value";
import { clearIfUnchanged } from "@/lib/clipboard";
import { seriousViolations } from "@/test/axe";

let clip = "";
const clipboard = {
  writeText: vi.fn(async (t: string) => {
    clip = t;
  }),
  readText: vi.fn(async () => clip),
};

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: false });
  clip = "";
  clipboard.writeText.mockClear();
  Object.defineProperty(navigator, "clipboard", { value: clipboard, configurable: true });
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ value: "hunter2" }), { status: 200 })),
  );
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const ui = () =>
  render(<SecretValue vault="kv" name="db" revealSeconds={10} clipboardSeconds={30} />);

async function click(name: string) {
  await act(async () => {
    screen.getByRole("button", { name }).click();
  });
}

async function tick(seconds: number) {
  for (let i = 0; i < seconds; i++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
  }
}

describe("SecretValue", () => {
  it("doesn't fetch until Reveal is pressed", async () => {
    ui();
    expect(fetch).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Secret value").textContent).not.toContain("hunter2");
    await click("Reveal");
    expect(fetch).toHaveBeenCalledOnce();
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect(init?.method).toBe("POST");
    expect(screen.getByLabelText("Secret value").textContent).toBe("hunter2");
  });

  it("hides again after the timeout", async () => {
    ui();
    await click("Reveal");
    expect(screen.getByText(/Hiding in 10s/)).toBeTruthy();
    await tick(10);
    expect(screen.getByLabelText("Secret value").textContent).not.toContain("hunter2");
  });

  it("hides when the tab is hidden", async () => {
    ui();
    await click("Reveal");
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(screen.getByLabelText("Secret value").textContent).not.toContain("hunter2");
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
  });

  it("copies, counts down, then clears the clipboard", async () => {
    ui();
    await click("Copy");
    expect(clip).toBe("hunter2");
    expect(screen.getByText(/Clipboard clears in 30s/)).toBeTruthy();
    // Copy doesn't put the value on screen.
    expect(screen.getByLabelText("Secret value").textContent).not.toContain("hunter2");
    await tick(29);
    expect(clip).toBe("hunter2");
    await tick(1);
    expect(clip).toBe("");
  });

  it("shows a plain error and keeps the value hidden", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: { title: "You don't have access", message: "Ask for it." } }),
        {
          status: 403,
        },
      ),
    );
    ui();
    await click("Reveal");
    expect(screen.getByRole("alert").textContent).toContain("You don't have access");
  });

  it("has no serious accessibility issues", async () => {
    vi.useRealTimers();
    const { container } = ui();
    expect(await seriousViolations(container)).toEqual([]);
  });
});

describe("clearIfUnchanged", () => {
  it("leaves the clipboard alone if something else was copied", async () => {
    clip = "something else";
    await clearIfUnchanged("hunter2", clipboard as unknown as Clipboard);
    expect(clip).toBe("something else");
  });
  it("clears if it can't read the clipboard", async () => {
    clip = "hunter2";
    const locked = {
      readText: vi.fn(async () => Promise.reject(new Error("denied"))),
      writeText: clipboard.writeText,
    };
    await clearIfUnchanged("hunter2", locked as unknown as Clipboard);
    expect(clip).toBe("");
  });
});
