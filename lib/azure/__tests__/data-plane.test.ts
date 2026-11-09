import { describe, expect, it } from "vitest";
import { isKeyVaultUri } from "../data-plane";

describe("isKeyVaultUri", () => {
  it.each([
    ["https://kv.vault.azure.net/", true],
    ["https://kv.vault.usgovcloudapi.net", true],
    ["http://kv.vault.azure.net/", false],
    ["https://evil.example/kv.vault.azure.net", false],
    ["https://kv.vault.azure.net.evil.example", false],
    ["not a url", false],
  ])("%s -> %s", (u, ok) => expect(isKeyVaultUri(u)).toBe(ok));
});
