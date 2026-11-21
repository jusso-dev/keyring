// Takes the README screenshots from the demo in tests/screenshots.rs.
//
//   cargo test --test screenshots -- --ignored --nocapture   # leave running
//   KEYRING_DEMO_COOKIE=keyring_session=... scripts/screenshots.sh
//
// scripts/screenshots.sh runs this with a pinned Playwright from npx, so
// the repo needs no package.json. Pictures go to docs/images/screenshots/.
// With KEYRING_SHOTS=guides it takes only the walkthrough guides' pictures,
// into docs/images/guides/, and leaves the README's alone.

import { createRequire } from "node:module";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// npx puts its install's node_modules/.bin on PATH. Load Playwright from
// there, since an ES module import can't see it.
function loadPlaywright() {
  for (const dir of (process.env.PATH || "").split(":")) {
    if (dir.endsWith(join("node_modules", ".bin")) && existsSync(join(dir, "..", "playwright", "package.json"))) {
      return createRequire(join(dir, "..", "noop.js"))("playwright");
    }
  }
  throw new Error("Playwright not found. Run this through scripts/screenshots.sh.");
}

const { chromium } = loadPlaywright();

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const guides = process.env.KEYRING_SHOTS === "guides";
const out = join(root, "docs", "images", guides ? "guides" : "screenshots");
mkdirSync(out, { recursive: true });

const port = process.env.KEYRING_DEMO_PORT || "3999";
const base = `http://127.0.0.1:${port}`;
const cookie = process.env.KEYRING_DEMO_COOKIE || "";
const [cookieName, cookieValue] = cookie.split("=");
if (!cookieName || !cookieValue) {
  throw new Error("Set KEYRING_DEMO_COOKIE to the line the demo prints, such as keyring_session=abc.");
}
const vault = "/v/kv-payments-prod";

const browser = await chromium.launch();

async function context(width, height, signedIn = true) {
  const ctx = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 1,
    colorScheme: "light",
    locale: "en-AU",
    timezoneId: "UTC",
    reducedMotion: "reduce",
  });
  if (signedIn) {
    await ctx.addCookies([{ name: cookieName, value: cookieValue, url: base }]);
  }
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: base });
  return ctx;
}

// Full-page shot, cut off at `maxHeight` so long pages stay readable.
async function shot(page, name, maxHeight = 1400) {
  await page.waitForLoadState("networkidle");
  const height = await page.evaluate(() => document.documentElement.scrollHeight);
  const width = page.viewportSize().width;
  await page.screenshot({
    path: join(out, `${name}.png`),
    clip: { x: 0, y: 0, width, height: Math.min(height, maxHeight) },
    fullPage: true,
    animations: "disabled",
    caret: "hide",
  });
  console.log(`wrote ${name}.png`);
}

async function visit(page, path, name, maxHeight) {
  const res = await page.goto(base + path);
  if (!res || res.status() !== 200) {
    throw new Error(`${path} answered ${res && res.status()}`);
  }
  await shot(page, name, maxHeight);
}

const desktop = await context(1280, 800);
const page = await desktop.newPage();

// The walkthrough guides: one picture of the main page of each, where the
// README's own pictures don't already show it.
if (guides) {
  await visit(page, "/search?q=payments", "01-search", 900);
  await visit(page, `${vault}/secrets/-/new?type=login`, "02-create-login");
  await visit(page, `${vault}/secrets/jwt-signing-config/edit`, "03-edit-details");
  await visit(
    page,
    `${vault}/secrets/db-connection-string/copy/review?to_vault=kv-platform-dev&to_name=db-connection-string&content_type=on&tags=on&dates=on&enabled=on`,
    "06-copy-review",
    900,
  );
  // Tick two secrets, then Review changes: the check before a bulk change.
  await page.goto(`${base}${vault}/secrets`);
  await page.check("#pick-redis-access-key");
  await page.check("#pick-smtp-relay-password");
  // "With selected" is closed until it is needed.
  await page.click("details.bulk > summary");
  await page.selectOption("#bulk-op", "tag_set");
  await page.fill("#bulk-tag-name", "env");
  await page.fill("#bulk-tag-value", "prod");
  await page.getByRole("button", { name: "Review changes" }).click();
  await page.waitForLoadState("networkidle");
  await shot(page, "07-bulk-review", 900);
  await visit(page, `${vault}/access`, "10-access", 900);
  await visit(page, `${vault}/my-access`, "10-my-access", 900);
  await visit(page, "/environments?group=payments", "17-environments", 950);
  await visit(
    page,
    "/environments/set?vaults=kv-payments-dev,kv-payments-test,kv-payments-prod&name=apple-pay-merchant-key",
    "17-environments-set",
    950,
  );
  await desktop.close();
  await browser.close();
  process.exit(0);
}

await visit(page, "/", "home", 1450);
await visit(page, "/reports/executive?submitted=1&client=Contoso+Financial&title=Executive+Key+Vault+Security+Brief&prepared_by=Platform+Security+Office&period=Nov+2026&theme=cobalt&scope=all&white_label=1&charts=1&vaults=1&envs=1&actions=1", "executive-reports", 1350);
await visit(page, "/vaults", "vaults", 900);
await visit(page, `${vault}/secrets`, "secrets-list");
await visit(page, `${vault}/secrets/db-connection-string`, "secret-detail");

// Reveal, then copy, so the clipboard countdown shows.
await page.getByRole("button", { name: "Show value" }).click();
await page.waitForURL(/\/reveal$/);
await page.getByRole("button", { name: "Copy" }).click();
await page.getByText("Copied.").waitFor();
await shot(page, "secret-reveal", 900);

// The new secret form after a save with an expiry date in the past.
await page.goto(`${base}${vault}/secrets/-/new`);
await page.fill("#name", "demo-new-secret");
await page.fill("#value", "demo-value");
await page.fill("#expires", "2024-01-31");
await page.getByRole("button", { name: "Create secret" }).click();
await page.waitForLoadState("networkidle");
await shot(page, "secret-form-error");

await visit(page, `${vault}/certificates`, "certificates-list", 900);
await visit(page, `${vault}/certificates/payments-api-tls`, "certificate-detail");
await visit(page, `${vault}/certificates/internal-gateway/renewal`, "certificate-renewal");
await visit(page, `${vault}/keys`, "keys-list", 900);
// Stops above the public key, whose JWK shows the mock's local address.
await visit(page, `${vault}/keys/payments-signing`, "key-detail", 650);
await visit(page, `${vault}/keys/payments-signing/rotation`, "key-rotation");
await visit(page, "/expiry", "expiry");
await visit(page, "/expiry/age", "credential-age");
await visit(page, "/vault-health", "vault-health");
await visit(page, `${vault}/audit`, "audit");
await visit(page, `${vault}/secrets/-/deleted`, "deleted", 900);
await desktop.close();

const mobile = await context(390, 844);
const phone = await mobile.newPage();
await visit(phone, `${vault}/secrets`, "mobile-secrets", 1250);
await mobile.close();

const anonymous = await context(1280, 800, false);
const signIn = await anonymous.newPage();
await visit(signIn, "/auth/sign-in", "sign-in", 800);
await anonymous.close();

await browser.close();
