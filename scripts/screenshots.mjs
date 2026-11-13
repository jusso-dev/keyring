// Takes the README screenshots from the demo in tests/screenshots.rs.
//
//   cargo test --test screenshots -- --ignored --nocapture   # leave running
//   KEYRING_DEMO_COOKIE=keyring_session=... scripts/screenshots.sh
//
// scripts/screenshots.sh runs this with a pinned Playwright from npx, so
// the repo needs no package.json. Pictures go to docs/images/screenshots/.

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
const out = join(root, "docs", "images", "screenshots");
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

await visit(page, "/", "home", 900);
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
