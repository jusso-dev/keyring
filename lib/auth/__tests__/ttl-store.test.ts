import { describe, expect, it } from "vitest";
import { TtlStore } from "../ttl-store";

function clock() {
  let t = 0;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe("TtlStore", () => {
  it("expires after the idle time", () => {
    const c = clock();
    const s = new TtlStore<string>({ absoluteMs: 1000, idleMs: 100, now: c.now });
    s.set("a", "1");
    c.advance(50);
    expect(s.get("a")).toBe("1");
    c.advance(90);
    expect(s.get("a")).toBe("1");
    c.advance(101);
    expect(s.get("a")).toBeUndefined();
  });
  it("expires after the absolute time even when used", () => {
    const c = clock();
    const s = new TtlStore<string>({ absoluteMs: 200, idleMs: 100, now: c.now });
    s.set("a", "1");
    for (let i = 0; i < 4; i++) {
      c.advance(60);
      s.get("a");
    }
    expect(s.get("a")).toBeUndefined();
  });
  it("take removes the entry", () => {
    const s = new TtlStore<string>({ absoluteMs: 1000, idleMs: 1000 });
    s.set("a", "1");
    expect(s.take("a")).toBe("1");
    expect(s.get("a")).toBeUndefined();
  });
});
