import { describe, expect, it } from "vitest";
import { requiredRole, toFriendlyError } from "../errors";

describe("toFriendlyError", () => {
  it("names the missing role on a 403", () => {
    const e = toFriendlyError(
      { statusCode: 403, code: "Forbidden" },
      { area: "secrets", action: "read" },
    );
    expect(e.kind).toBe("forbidden");
    expect(e.role).toBe("Key Vault Secrets User");
    expect(e.message).toBe(
      "You don't have permission to see secrets here. Ask your Azure admin for the Key Vault Secrets User role on this vault.",
    );
  });

  it("asks for the officer role when writing", () => {
    expect(toFriendlyError({ statusCode: 403 }, { area: "keys", action: "write" }).role).toBe(
      "Key Vault Crypto Officer",
    );
  });

  it("spots a private vault", () => {
    expect(toFriendlyError({ statusCode: 403, code: "ForbiddenByConnection" }).kind).toBe(
      "private-network",
    );
  });

  it("handles 401, 404, 409, 429 and network errors", () => {
    expect(toFriendlyError({ statusCode: 401 }).kind).toBe("signed-out");
    expect(toFriendlyError({ statusCode: 404 }, { area: "secrets", name: "db-pass" }).message).toBe(
      'We couldn\'t find "db-pass". It may have been deleted or renamed.',
    );
    expect(toFriendlyError({ statusCode: 409, code: "ObjectIsDeletedButRecoverable" }).kind).toBe(
      "soft-deleted",
    );
    expect(toFriendlyError({ statusCode: 409, code: "Conflict" }).kind).toBe("conflict");
    expect(toFriendlyError({ statusCode: 429 }).kind).toBe("throttled");
    expect(toFriendlyError({ code: "ENOTFOUND" }).kind).toBe("network");
    expect(toFriendlyError(new Error("weird")).kind).toBe("unknown");
  });

  it("never echoes the raw error message", () => {
    const raw = "secret-value-123 leaked";
    for (const status of [401, 403, 404, 409, 429, 500]) {
      const e = toFriendlyError({ statusCode: status, message: raw });
      expect(e.message).not.toContain("secret-value-123");
      expect(e.title).not.toContain("secret-value-123");
    }
  });

  it("uses plain copy with no em dashes", () => {
    for (const status of [401, 403, 404, 409, 429, 500]) {
      expect(toFriendlyError({ statusCode: status }).message).not.toMatch(/—/);
    }
  });
});

describe("requiredRole", () => {
  it("maps areas to Key Vault roles", () => {
    expect(requiredRole("certificates", "write")).toBe("Key Vault Certificates Officer");
  });
});
