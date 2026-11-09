// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ComingSoon, Empty, ErrorNotice, Loading } from "../ui/states";
import { toFriendlyError } from "@/lib/errors";
import { seriousViolations } from "@/test/axe";

vi.mock("next/navigation", () => ({ usePathname: () => "/secrets" }));
const { SideNav } = await import("../side-nav");

describe("shared states", () => {
  it("loading is announced", () => {
    render(<Loading label="Loading secrets" />);
    expect(screen.getByRole("status").textContent).toContain("Loading secrets");
  });

  it("errors are alerts", () => {
    render(<ErrorNotice error={toFriendlyError({ statusCode: 403 })} />);
    expect(screen.getByRole("alert").textContent).toContain("You don't have access");
  });

  it("have no serious accessibility issues", async () => {
    const { container } = render(
      <main>
        <SideNav />
        <Loading />
        <Empty title="No secrets yet">Add one to get started.</Empty>
        <ErrorNotice error={toFriendlyError({ statusCode: 429 })} />
        <ComingSoon title="Keys" />
      </main>,
    );
    expect(await seriousViolations(container)).toEqual([]);
  });

  it("marks the current section in the nav", () => {
    render(<SideNav />);
    expect(screen.getByRole("link", { current: "page" }).textContent).toContain("Secrets");
  });
});
