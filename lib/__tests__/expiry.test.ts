import { describe, expect, it } from "vitest";
import { DAY_MS, expiryState } from "../expiry";
import { formatDate, formatDateTime } from "../format";

const now = Date.UTC(2026, 10, 9);

describe("expiryState", () => {
  it.each([
    [undefined, "none"],
    [new Date(now - 1), "expired"],
    [new Date(now), "expired"],
    [new Date(now + 5 * DAY_MS), "soon"],
    [new Date(now + 30 * DAY_MS), "soon"],
    [new Date(now + 31 * DAY_MS), "upcoming"],
    [new Date(now + 91 * DAY_MS), "ok"],
    ["not a date", "none"],
  ])("%s -> %s", (d, s) => expect(expiryState(d as Date | undefined, now)).toBe(s));
});

describe("format", () => {
  it("uses DD-MM-YYYY", () => {
    expect(formatDate("2026-03-04T10:00:00Z")).toBe("04-03-2026");
    expect(formatDateTime("2026-03-04T10:05:00Z")).toBe("04-03-2026 10:05 UTC");
    expect(formatDate(undefined)).toBe("");
  });
});
