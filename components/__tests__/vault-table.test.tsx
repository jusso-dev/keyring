// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { VaultTable, type VaultRow } from "../vault-table";
import { seriousViolations } from "@/test/axe";

const make = (name: string, sub: string, subName: string): VaultRow => ({
  id: `/subs/${sub}/${name}`,
  name,
  subscriptionId: sub,
  subscriptionName: subName,
  resourceGroup: "rg",
  location: "australiaeast",
  rbac: true,
  softDelete: true,
  purgeProtection: false,
  publicNetworkAccess: "Enabled",
  tags: {},
});

describe("VaultTable", () => {
  it("filters as you type", async () => {
    const user = userEvent.setup();
    render(<VaultTable vaults={[make("kv-pay", "a", "Prod"), make("kv-web", "b", "Dev")]} />);
    expect(screen.getAllByRole("row")).toHaveLength(3);
    await user.type(screen.getByLabelText("Search"), "web");
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "kv-web" }).getAttribute("href")).toBe(
      "/vaults/kv-web/secrets",
    );
  });

  it("shows vaults in pages", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 120 }, (_, i) => make(`kv-${i}`, "a", "Prod"));
    render(<VaultTable vaults={many} />);
    expect(screen.getAllByRole("row")).toHaveLength(51);
    await user.click(screen.getByRole("button", { name: "Show more" }));
    expect(screen.getAllByRole("row")).toHaveLength(101);
  });

  it("has no serious accessibility issues", async () => {
    const { container } = render(<VaultTable vaults={[make("kv", "a", "Prod")]} />);
    expect(await seriousViolations(container)).toEqual([]);
  });
});
