import { describe, expect, it } from "vitest";
import { safeReturnTo, signInPath } from "../return-to";

describe("safeReturnTo", () => {
  it.each([
    ["/vaults", "/vaults"],
    ["/vaults?q=prod", "/vaults?q=prod"],
    [null, "/"],
    ["", "/"],
    ["https://evil.example", "/"],
    ["//evil.example/path", "/"],
    ["/\\evil.example", "/"],
    ["javascript:alert(1)", "/"],
    ["/auth/callback?code=x", "/"],
    ["/a\nb", "/"],
  ])("%s -> %s", (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });
});

describe("signInPath", () => {
  it("keeps the return path and reason", () => {
    expect(signInPath("/vaults?x=1", "expired")).toBe(
      "/sign-in?returnTo=%2Fvaults%3Fx%3D1&reason=expired",
    );
  });
  it("is bare for the home page", () => {
    expect(signInPath("/")).toBe("/sign-in");
  });
});
