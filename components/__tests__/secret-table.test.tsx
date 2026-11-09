// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { SecretTable, type SecretRow } from "../secrets/secret-table";
import { seriousViolations } from "@/test/axe";

const rows: SecretRow[] = [
  {
    name: "db-password",
    enabled: true,
    contentType: "",
    tags: { env: "prod" },
    expiresOn: "2000-01-01T00:00:00Z",
  },
  { name: "api-key", enabled: false, contentType: "text/plain", tags: {} },
];

describe("SecretTable", () => {
  it("marks expired and disabled secrets", () => {
    render(<SecretTable items={rows} baseHref="/vaults/kv/secrets" />);
    expect(screen.getByText("Expired")).toBeTruthy();
    expect(screen.getByText("Disabled")).toBeTruthy();
  });

  it("searches by name and tag", async () => {
    const user = userEvent.setup();
    render(<SecretTable items={rows} baseHref="/vaults/kv/secrets" />);
    await user.type(screen.getByLabelText("Tag"), "env=prod");
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "db-password" }).getAttribute("href")).toBe(
      "/vaults/kv/secrets/db-password",
    );
  });

  it("pages large lists", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 75 }, (_, i) => ({ ...rows[1], name: `s-${i}` }));
    render(<SecretTable items={many} baseHref="/x" />);
    expect(screen.getAllByRole("row")).toHaveLength(51);
    await user.click(screen.getByRole("button", { name: "Show more" }));
    expect(screen.getAllByRole("row")).toHaveLength(76);
  });

  it("has no serious accessibility issues", async () => {
    const { container } = render(<SecretTable items={rows} baseHref="/x" />);
    expect(await seriousViolations(container)).toEqual([]);
  });
});
