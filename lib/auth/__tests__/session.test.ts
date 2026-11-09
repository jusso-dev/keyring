import { beforeEach, describe, expect, it, vi } from "vitest";

const cookieJar = new Map<string, string>();
const headerJar = new Map<string, string>();

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (n: string) => (cookieJar.has(n) ? { value: cookieJar.get(n) } : undefined),
  }),
  headers: async () => ({ get: (n: string) => headerJar.get(n) ?? null }),
}));
vi.mock("next/navigation", () => ({
  redirect: (url: string) => {
    throw new Error(`REDIRECT ${url}`);
  },
}));
vi.mock("@/lib/config", () => ({ getConfig: () => ({ sessionSecret: "s".repeat(32) }) }));

const { requireSession } = await import("../session");
const { SESSION_COOKIE, signId } = await import("../cookie");
const { stores } = await import("../session-store");

beforeEach(() => {
  cookieJar.clear();
  headerJar.clear();
  headerJar.set("x-keyring-path", "/vaults?q=1");
});

describe("requireSession", () => {
  it("returns the session when the cookie is valid", async () => {
    stores().sessions.set("good", { id: "good" } as never);
    cookieJar.set(SESSION_COOKIE, signId("good", "s".repeat(32)));
    await expect(requireSession()).resolves.toMatchObject({ id: "good" });
  });

  it("sends a new visitor to sign-in and remembers the page", async () => {
    await expect(requireSession()).rejects.toThrow("REDIRECT /sign-in?returnTo=%2Fvaults%3Fq%3D1");
  });

  it("explains when a session has ended", async () => {
    cookieJar.set(SESSION_COOKIE, signId("gone", "s".repeat(32)));
    await expect(requireSession()).rejects.toThrow(/reason=expired/);
  });
});
