import { afterEach, describe, expect, it, vi } from "vitest";
import { log, scrub } from "../log";

afterEach(() => vi.restoreAllMocks());

describe("log", () => {
  it("redacts JWTs and long token-like strings", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(scrub(`token ${jwt}`)).toBe("token [redacted]");
    expect(scrub("a".repeat(48))).toBe("[redacted]");
    expect(scrub("normal message")).toBe("normal message");
  });
  it("writes JSON lines with scrubbed fields", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    log.info("hello", { detail: "b".repeat(50), status: 403 });
    const line = JSON.parse(spy.mock.calls[0][0] as string);
    expect(line).toMatchObject({
      level: "info",
      message: "hello",
      detail: "[redacted]",
      status: 403,
    });
  });
});
