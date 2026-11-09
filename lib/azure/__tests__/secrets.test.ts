import type { SecretProperties } from "@azure/keyvault-secrets";
import { describe, expect, it, vi } from "vitest";
import { filterSecrets } from "@/lib/secret-filter";
import {
  MAX_SECRETS,
  getSecretProperties,
  isSecretName,
  isVersionId,
  listSecrets,
  toSecretItem,
  type SecretsReader,
  type VersionsReader,
} from "../secrets";

const props = (name: string, extra: Partial<SecretProperties> = {}): SecretProperties =>
  ({
    name,
    vaultUrl: "https://kv.vault.azure.net",
    version: "a".repeat(32),
    enabled: true,
    createdOn: new Date("2026-01-01T00:00:00Z"),
    updatedOn: new Date("2026-01-02T00:00:00Z"),
    tags: {},
    ...extra,
  }) as SecretProperties;

function pagedReader(pages: SecretProperties[][]) {
  const byPage = vi.fn(async function* () {
    for (const p of pages) yield p;
  });
  const listPropertiesOfSecrets = vi.fn(() => ({ byPage }));
  return {
    reader: { listPropertiesOfSecrets } as unknown as SecretsReader,
    listPropertiesOfSecrets,
    byPage,
  };
}

describe("listSecrets", () => {
  it("lists properties across pages without reading values", async () => {
    const { reader, byPage } = pagedReader([
      [props("b"), props("a")],
      [props("c"), props("cert", { managed: true } as Partial<SecretProperties>)],
    ]);
    const { items, truncated } = await listSecrets(reader);
    expect(items.map((i) => i.name)).toEqual(["a", "b", "c"]);
    expect(truncated).toBe(false);
    expect(byPage).toHaveBeenCalledOnce();
    for (const i of items) expect(i).not.toHaveProperty("value");
  });

  it("only uses the properties list, never getSecret", async () => {
    const { reader } = pagedReader([[props("a")]]);
    const getSecret = vi.fn();
    Object.assign(reader, { getSecret });
    await listSecrets(reader);
    expect(getSecret).not.toHaveBeenCalled();
  });

  it("stops at the cap", async () => {
    const big = Array.from({ length: MAX_SECRETS + 10 }, (_, i) => props(`s${i}`));
    const { reader } = pagedReader([big]);
    const { items, truncated } = await listSecrets(reader);
    expect(items).toHaveLength(MAX_SECRETS);
    expect(truncated).toBe(true);
  });
});

describe("toSecretItem", () => {
  it("drops anything value-like and uses ISO dates", () => {
    const withValue = { ...props("x"), value: "hunter2" } as unknown as SecretProperties;
    const item = toSecretItem(withValue);
    expect(JSON.stringify(item)).not.toContain("hunter2");
    expect(item.createdOn).toBe("2026-01-01T00:00:00.000Z");
  });
});

describe("getSecretProperties", () => {
  it("returns the newest version", async () => {
    const reader = {
      listPropertiesOfSecretVersions: vi.fn(async function* () {
        yield props("x", {
          version: "1".repeat(32),
          createdOn: new Date("2026-01-01"),
        } as Partial<SecretProperties>);
        yield props("x", {
          version: "2".repeat(32),
          createdOn: new Date("2026-02-01"),
        } as Partial<SecretProperties>);
      }),
    } as unknown as VersionsReader;
    expect((await getSecretProperties(reader, "x"))?.version).toBe("2".repeat(32));
  });
});

describe("filterSecrets", () => {
  const now = Date.UTC(2026, 10, 9);
  const items = [
    toSecretItem(props("db-password", { tags: { env: "prod" } })),
    toSecretItem(props("api-key", { enabled: false })),
    toSecretItem(props("old", { expiresOn: new Date(now - 1000) } as Partial<SecretProperties>)),
    toSecretItem(
      props("later", { expiresOn: new Date(now + 200 * 86400000) } as Partial<SecretProperties>),
    ),
  ];
  it("filters by name, tag, expiring and disabled", () => {
    const names = (f: Parameters<typeof filterSecrets>[1]) =>
      filterSecrets(items, f, now).map((s) => s.name);
    expect(names({ q: "DB" })).toEqual(["db-password"]);
    expect(names({ tag: "env=prod" })).toEqual(["db-password"]);
    expect(names({ expiring: true })).toEqual(["old"]);
    expect(names({ disabled: true })).toEqual(["api-key"]);
  });
});

describe("names", () => {
  it("validates secret names and versions", () => {
    expect(isSecretName("db-password-1")).toBe(true);
    expect(isSecretName("db_password")).toBe(false);
    expect(isSecretName("a".repeat(128))).toBe(false);
    expect(isVersionId("0123456789abcdef0123456789abcdef")).toBe(true);
    expect(isVersionId("../etc")).toBe(false);
  });
});
