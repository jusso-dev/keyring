import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const SECRET = "s3cr3t-Value-that-must-not-leak";
const getSecret = vi.fn(async () => ({ value: SECRET }));
let session: object | undefined = { id: "s" };

vi.mock("@/lib/config", () => ({ getConfig: () => ({ baseUrl: "https://keyring.example.com" }) }));
vi.mock("@/lib/auth/session", () => ({ getSession: async () => session }));
vi.mock("@/lib/azure/vault-context", () => ({
  findVault: async (n: string) =>
    n === "kv" ? { name: "kv", vaultUri: "https://kv.vault.azure.net/" } : undefined,
}));
vi.mock("@/lib/azure/data-plane", () => ({ secretsFor: async () => ({ getSecret }) }));
vi.mock("next/headers", () => ({ headers: async () => new Headers() }));

const { POST } = await import("../route");

function call(opts: { origin?: string; vault?: string; name?: string; body?: unknown } = {}) {
  const req = new Request("https://keyring.example.com/api/vaults/kv/secrets/db/value", {
    method: "POST",
    headers: {
      origin: opts.origin ?? "https://keyring.example.com",
      "content-type": "application/json",
    },
    body: JSON.stringify(opts.body ?? {}),
  });
  return POST(req, {
    params: Promise.resolve({ vault: opts.vault ?? "kv", name: opts.name ?? "db" }),
  } as never);
}

let logs: string[];
beforeEach(() => {
  session = { id: "s" };
  getSecret.mockClear();
  logs = [];
  for (const m of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
      logs.push(a.map(String).join(" "));
    });
  }
});
afterEach(() => vi.restoreAllMocks());

describe("POST secret value", () => {
  it("returns the value with no-store", async () => {
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ value: SECRET });
    expect(res.headers.get("cache-control")).toContain("no-store");
    expect(getSecret).toHaveBeenCalledWith("db", {});
  });

  it("reads a specific version", async () => {
    await call({ body: { version: "a".repeat(32) } });
    expect(getSecret).toHaveBeenCalledWith("db", { version: "a".repeat(32) });
  });

  it("rejects bad versions and names without calling Azure", async () => {
    expect((await call({ body: { version: "../x" } })).status).toBe(400);
    expect((await call({ name: "bad_name" })).status).toBe(400);
    expect(getSecret).not.toHaveBeenCalled();
  });

  it("refuses cross-site requests", async () => {
    const res = await call({ origin: "https://evil.example" });
    expect(res.status).toBe(403);
    expect(getSecret).not.toHaveBeenCalled();
  });

  it("needs a session", async () => {
    session = undefined;
    expect((await call()).status).toBe(401);
    expect(getSecret).not.toHaveBeenCalled();
  });

  it("maps a 403 from Key Vault with the role name and no-store", async () => {
    getSecret.mockRejectedValueOnce(
      Object.assign(new Error(`denied ${SECRET}`), { statusCode: 403 }),
    );
    const res = await call();
    expect(res.status).toBe(403);
    expect(res.headers.get("cache-control")).toContain("no-store");
    const body = await res.json();
    expect(body.error.message).toContain("Key Vault Secrets User");
    expect(JSON.stringify(body)).not.toContain(SECRET);
  });

  it("never writes the value to the logs", async () => {
    await call();
    getSecret.mockRejectedValueOnce(Object.assign(new Error(SECRET), { statusCode: 500 }));
    await call();
    expect(logs.join("\n")).not.toContain(SECRET);
  });
});
