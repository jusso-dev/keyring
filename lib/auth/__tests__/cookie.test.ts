import { describe, expect, it } from "vitest";
import { cookieOptions, newId, signId, verifySignedId } from "../cookie";

const secret = "x".repeat(32);

describe("signed ids", () => {
  it("round-trips", () => {
    const id = newId();
    expect(verifySignedId(signId(id, secret), secret)).toBe(id);
  });
  it("rejects tampering and other secrets", () => {
    const signed = signId(newId(), secret);
    expect(verifySignedId(signed.replace(/^./, "Z"), secret)).toBeUndefined();
    expect(verifySignedId(signed, "y".repeat(32))).toBeUndefined();
    expect(verifySignedId("nodot", secret)).toBeUndefined();
    expect(verifySignedId(undefined, secret)).toBeUndefined();
  });
});

describe("cookieOptions", () => {
  it("is secure, http-only and lax in production", () => {
    expect(cookieOptions("https://keyring.example.com")).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    });
  });
  it("allows plain http on localhost only", () => {
    expect(cookieOptions("http://localhost:3000").secure).toBe(false);
    expect(cookieOptions("http://keyring.example.com").secure).toBe(true);
  });
});
