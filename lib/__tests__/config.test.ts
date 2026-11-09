import { describe, expect, it } from "vitest";
import { parseConfig } from "../config";

const base = {
  ENTRA_TENANT_ID: "tenant",
  ENTRA_CLIENT_ID: "client",
  ENTRA_CLIENT_SECRET: "secret",
  APP_BASE_URL: "http://localhost:3000/",
  SESSION_SECRET: "s".repeat(32),
};

describe("parseConfig", () => {
  it("reads settings and applies defaults", () => {
    const c = parseConfig(base);
    expect(c.baseUrl).toBe("http://localhost:3000");
    expect(c.apiScope).toBe("api://client/access_as_user");
    expect(c.allowPurge).toBe(false);
  });
  it("only turns purge on for true", () => {
    expect(parseConfig({ ...base, KEYRING_ALLOW_PURGE: "TRUE" }).allowPurge).toBe(true);
    expect(parseConfig({ ...base, KEYRING_ALLOW_PURGE: "yes" }).allowPurge).toBe(false);
  });
  it("names the missing setting without echoing values", () => {
    expect(() => parseConfig({ ...base, ENTRA_CLIENT_SECRET: "" })).toThrow(/ENTRA_CLIENT_SECRET/);
    expect(() => parseConfig({ ...base, SESSION_SECRET: "short" })).toThrow(/at least 32/);
  });
});
