import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Keyring must only ever call Azure as the signed-in person. These would give
// the app an identity of its own, so they must not appear in app code.
const BANNED = [
  "DefaultAzureCredential",
  "ManagedIdentityCredential",
  "ManagedIdentityApplication",
  "ClientSecretCredential",
  "ClientCertificateCredential",
  "EnvironmentCredential",
  "AzureCliCredential",
  "WorkloadIdentityCredential",
  "ChainedTokenCredential",
  "acquireTokenByClientCredential",
  "@azure/identity",
];

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (name === "node_modules" || name === "__tests__" || name.startsWith(".")) return [];
    return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx)$/.test(name) ? [p] : [];
  });
}

describe("no app identity", () => {
  it("app code never uses an app-only or managed identity credential", () => {
    const offenders: string[] = [];
    for (const f of [...files("app"), ...files("lib"), ...files("components"), "proxy.ts"]) {
      const src = readFileSync(f, "utf8");
      for (const word of BANNED) if (src.includes(word)) offenders.push(`${f}: ${word}`);
    }
    expect(offenders).toEqual([]);
  });

  it("@azure/identity is not a dependency", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8"));
    expect({ ...pkg.dependencies, ...pkg.devDependencies }).not.toHaveProperty("@azure/identity");
  });
});
