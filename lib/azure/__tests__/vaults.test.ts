import { describe, expect, it, vi } from "vitest";
import {
  MAX_PAGES,
  PAGE_SIZE,
  VAULTS_QUERY,
  buildVaultQuery,
  filterVaults,
  isVaultName,
  listVaults,
  mapVaultRow,
  subscriptionsOf,
  type ResourceGraphLike,
} from "../vaults";

const row = (name: string, sub = "sub-a", extra: Record<string, unknown> = {}) => ({
  id: `/subscriptions/${sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/${name}`,
  name,
  resourceGroup: "rg",
  subscriptionId: sub,
  subscriptionName: sub === "sub-a" ? "Production" : "Development",
  location: "australiaeast",
  vaultUri: `https://${name}.vault.azure.net/`,
  enableRbacAuthorization: true,
  enableSoftDelete: true,
  enablePurgeProtection: false,
  publicNetworkAccess: "Enabled",
  tags: { env: "prod" },
  ...extra,
});

describe("buildVaultQuery", () => {
  it("asks for full pages as objects", () => {
    expect(buildVaultQuery()).toEqual({
      query: VAULTS_QUERY,
      options: { top: PAGE_SIZE, resultFormat: "objectArray" },
    });
    expect(buildVaultQuery("tok").options).toMatchObject({ skipToken: "tok" });
  });
  it("queries vaults with subscription names and no user input", () => {
    expect(VAULTS_QUERY).toMatch(/microsoft\.keyvault\/vaults/);
    expect(VAULTS_QUERY).toMatch(/subscriptionName/);
    expect(VAULTS_QUERY).not.toMatch(/\$\{/);
  });
});

describe("mapVaultRow", () => {
  it("maps properties", () => {
    expect(mapVaultRow(row("kv-one"))).toMatchObject({
      name: "kv-one",
      subscriptionName: "Production",
      rbac: true,
      softDelete: true,
      purgeProtection: false,
      publicNetworkAccess: "Enabled",
      tags: { env: "prod" },
    });
  });
  it("copes with missing fields", () => {
    const v = mapVaultRow({ name: "kv-old", subscriptionId: "s" });
    expect(v).toMatchObject({
      subscriptionName: "s",
      rbac: false,
      softDelete: true,
      vaultUri: "https://kv-old.vault.azure.net/",
      tags: {},
    });
  });
  it("spots private vaults", () => {
    expect(
      mapVaultRow(row("kv", "s", { publicNetworkAccess: "Disabled" })).publicNetworkAccess,
    ).toBe("Disabled");
  });
});

describe("listVaults", () => {
  it("pages through more than 1000 vaults across subscriptions", async () => {
    const pages = [
      { data: Array.from({ length: 1000 }, (_, i) => row(`kv-a-${i}`)), skipToken: "p2" },
      { data: Array.from({ length: 1000 }, (_, i) => row(`kv-b-${i}`, "sub-b")), skipToken: "p3" },
      { data: [row("kv-last", "sub-b")] },
    ];
    const resources = vi.fn(async () => pages.shift()!);
    const vaults = await listVaults({ resources } as unknown as ResourceGraphLike);
    expect(vaults).toHaveLength(2001);
    expect(resources).toHaveBeenCalledTimes(3);
    expect(resources.mock.calls.map((c) => (c as unknown[])[0])).toMatchObject([
      { options: {} },
      { options: { skipToken: "p2" } },
      { options: { skipToken: "p3" } },
    ]);
    expect(subscriptionsOf(vaults).map((s) => s.name)).toEqual(["Development", "Production"]);
  });

  it("stops after a fixed number of pages", async () => {
    const resources = vi.fn(async () => ({ data: [row("kv")], skipToken: "again" }));
    await listVaults({ resources } as unknown as ResourceGraphLike);
    expect(resources).toHaveBeenCalledTimes(MAX_PAGES);
  });

  it("returns an empty list when there are none", async () => {
    const resources = vi.fn(async () => ({ data: [] }));
    expect(await listVaults({ resources } as unknown as ResourceGraphLike)).toEqual([]);
  });
});

describe("filterVaults", () => {
  const vaults = [
    mapVaultRow(row("kv-payments")),
    mapVaultRow(row("kv-web", "sub-b", { tags: { env: "dev", team: "web" } })),
  ];
  it("filters by name, subscription and tag", () => {
    expect(filterVaults(vaults, { q: "PAY" }).map((v) => v.name)).toEqual(["kv-payments"]);
    expect(filterVaults(vaults, { subscription: "sub-b" }).map((v) => v.name)).toEqual(["kv-web"]);
    expect(filterVaults(vaults, { tag: "team" }).map((v) => v.name)).toEqual(["kv-web"]);
    expect(filterVaults(vaults, { tag: "env=prod" }).map((v) => v.name)).toEqual(["kv-payments"]);
    expect(filterVaults(vaults, {})).toHaveLength(2);
  });
});

describe("isVaultName", () => {
  it.each([
    ["kv-prod", true],
    ["a1b", true],
    ["ab", false],
    ["1abc", false],
    ["kv--x", false],
    ["kv-", false],
    ["a".repeat(25), false],
  ])("%s -> %s", (n, ok) => expect(isVaultName(n)).toBe(ok));
});
