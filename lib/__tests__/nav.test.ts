import { describe, expect, it } from "vitest";
import { NAV, isActive, parseVaultPath, vaultHref } from "../nav";

const item = (label: string) => NAV.find((n) => n.label === label)!;

describe("nav", () => {
  it("parses vault paths", () => {
    expect(parseVaultPath("/vaults/kv-a/secrets/db")).toEqual({
      vault: "kv-a",
      section: "secrets",
    });
    expect(parseVaultPath("/vaults")).toEqual({});
  });
  it("highlights the section inside a vault", () => {
    expect(isActive("/vaults/kv-a/keys", item("Keys"))).toBe(true);
    expect(isActive("/vaults/kv-a/keys", item("Vaults"))).toBe(false);
    expect(isActive("/vaults", item("Vaults"))).toBe(true);
  });
  it("encodes vault names", () => {
    expect(vaultHref("kv a", "keys")).toBe("/vaults/kv%20a/keys");
  });
});
