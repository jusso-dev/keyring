// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "../ui/confirm-dialog";
import { seriousViolations } from "@/test/axe";

function setup() {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  const utils = render(
    <ConfirmDialog
      open
      title="Delete secret"
      description="This moves db-password to deleted secrets. You can recover it later."
      confirmText="db-password"
      actionLabel="Delete"
      onConfirm={onConfirm}
      onCancel={onCancel}
    />,
  );
  return { ...utils, onConfirm, onCancel };
}

describe("ConfirmDialog", () => {
  it("keeps the button disabled until the name is typed exactly", async () => {
    const user = userEvent.setup();
    const { onConfirm } = setup();
    const button = screen.getByRole("button", { name: "Delete", hidden: true });
    const input = screen.getByLabelText(/to confirm/, { selector: "input" });
    expect(button).toHaveProperty("disabled", true);
    await user.type(input, "db-passwor");
    expect(button).toHaveProperty("disabled", true);
    await user.type(input, "d");
    expect(button).toHaveProperty("disabled", false);
    await user.click(button);
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("is case sensitive", async () => {
    const user = userEvent.setup();
    setup();
    await user.type(screen.getByLabelText(/to confirm/, { selector: "input" }), "DB-PASSWORD");
    expect(screen.getByRole("button", { name: "Delete", hidden: true })).toHaveProperty(
      "disabled",
      true,
    );
  });

  it("doesn't confirm on Enter when the name is wrong", async () => {
    const user = userEvent.setup();
    const { onConfirm } = setup();
    await user.type(screen.getByLabelText(/to confirm/, { selector: "input" }), "nope{Enter}");
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("cancels", async () => {
    const user = userEvent.setup();
    const { onCancel } = setup();
    await user.click(screen.getByRole("button", { name: "Cancel", hidden: true }));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it("has no serious accessibility issues", async () => {
    const { container } = setup();
    expect(await seriousViolations(container)).toEqual([]);
  });
});
