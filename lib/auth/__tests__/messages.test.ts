import { describe, expect, it } from "vitest";
import { signInMessage } from "../messages";

describe("signInMessage", () => {
  it("has a short message for an ended session", () => {
    expect(signInMessage({ reason: "expired" })).toBe(
      "Your session ended. Sign in again to carry on.",
    );
  });
  it("says nothing on a normal visit", () => {
    expect(signInMessage({})).toBeUndefined();
  });
});
