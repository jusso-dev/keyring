import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { proxy } from "@/proxy";

describe("proxy", () => {
  it("sends people without a session to sign-in with the page they wanted", () => {
    const res = proxy(new NextRequest("https://keyring.example.com/vaults?q=1"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe(
      "https://keyring.example.com/sign-in?returnTo=%2Fvaults%3Fq%3D1",
    );
  });
  it("lets sign-in pages through", () => {
    const res = proxy(new NextRequest("https://keyring.example.com/sign-in"));
    expect(res.headers.get("location")).toBeNull();
  });
  it("lets requests with a session cookie through for the real check", () => {
    const res = proxy(
      new NextRequest("https://keyring.example.com/vaults", {
        headers: { cookie: "keyring_session=abc.def" },
      }),
    );
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("proxy and sign-out", () => {
  it("lets sign-out reach its own origin check", () => {
    const res = proxy(
      new NextRequest("https://keyring.example.com/auth/sign-out", { method: "POST" }),
    );
    expect(res.headers.get("location")).toBeNull();
  });
});
