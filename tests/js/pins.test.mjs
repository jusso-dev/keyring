// Tests for static/pins.js. Run with `node --test tests/js/`. No packages.

import test from "node:test";
import assert from "node:assert/strict";
import { page, Storage } from "./stubs.mjs";

const KEY = "keyring.pins";

const secret = (name = "db-password", vault = "kv-test") => ({
  kind: "secret",
  vault,
  name,
  path: `/v/${vault}/secrets/${name}`,
});
const vaultEntry = (vault = "kv-test") => ({ kind: "vault", vault, name: vault, path: `/v/${vault}/secrets` });

function stored(storage) {
  return JSON.parse(storage.getItem(KEY));
}

// A secret's page, as templates/secrets/detail.html renders its heading.
function itemPage(storage, name = "db-password") {
  return page(
    (h) => [
      h("p", { class: "back-link" }),
      h("h1", { class: "mono", "data-pin": "secret", "data-pin-vault": "kv-test", "data-pin-name": name, text: name }),
      h("p", { text: "badges" }),
    ],
    { script: "pins.js", storage },
  );
}

// The home page or the vault list.
function homePage(storage) {
  return page((h) => [h("h1", { text: "Keyring" }), h("div", { class: "pins-box", "data-pins": "", hidden: true })], {
    script: "pins.js",
    storage,
  });
}

const all = (root, sel) => root.querySelectorAll(sel);

test("opening an item records it as recent, newest first, at most 10", () => {
  const storage = new Storage();
  for (let i = 0; i < 12; i++) itemPage(storage, `s${i}`);
  itemPage(storage, "s5");
  const recent = stored(storage).recent;
  assert.equal(recent.length, 10);
  assert.equal(recent[0].name, "s5");
  assert.equal(recent.filter((e) => e.name === "s5").length, 1);
  assert.deepEqual(Object.keys(recent[0]).sort(), ["kind", "name", "path", "vault"]);
});

test("the star is a button with a pressed state and a name for screen readers", () => {
  const storage = new Storage();
  const { main } = itemPage(storage);
  const [button] = all(main, "button");
  assert.equal(button.type, "button");
  assert.equal(button.getAttribute("aria-pressed"), "false");
  assert.equal(button.textContent, "Pin db-password");
  // Right under the heading.
  assert.equal(main.children[2].className, "pin-row");
  button.click();
  assert.equal(button.getAttribute("aria-pressed"), "true");
  assert.deepEqual(stored(storage).pinned, [secret()]);
  button.click();
  assert.equal(button.getAttribute("aria-pressed"), "false");
  assert.deepEqual(stored(storage).pinned, []);
});

test("a vault list page pins the vault and isn't recorded as recent", () => {
  const storage = new Storage();
  const { main } = page(
    (h) => [h("h1", { "data-pin": "vault", "data-pin-vault": "kv-test", text: "Secrets" })],
    { script: "pins.js", storage },
  );
  all(main, "button")[0].click();
  assert.deepEqual(stored(storage), { pinned: [vaultEntry()], recent: [] });
});

test("the pinned list is capped at 50", () => {
  const pinned = Array.from({ length: 50 }, (_, i) => secret(`p${i}`));
  const storage = new Storage({ [KEY]: JSON.stringify({ pinned, recent: [] }) });
  const { main } = itemPage(storage, "new-one");
  all(main, "button")[0].click();
  const after = stored(storage).pinned;
  assert.equal(after.length, 50);
  assert.equal(after[0].name, "new-one");
});

test("home shows Pinned and Recently opened as safe links, with Clear", () => {
  const storage = new Storage({ [KEY]: JSON.stringify({ pinned: [vaultEntry()], recent: [secret()] }) });
  const { main } = homePage(storage);
  const mount = main.querySelector("div");
  assert.equal(mount.hidden, false);
  assert.deepEqual(
    all(mount, "h2").map((h) => h.textContent),
    ["Pinned", "Recently opened"],
  );
  assert.deepEqual(
    all(mount, "a").map((a) => [a.getAttribute("href"), a.textContent]),
    [
      ["/v/kv-test/secrets", "kv-test"],
      ["/v/kv-test/secrets/db-password", "db-password"],
    ],
  );
  const clear = all(mount, "button")[0];
  assert.equal(clear.textContent, "Clear");
  assert.match(mount.textContent, /cleared when you sign out/);
  clear.click();
  assert.equal(storage.getItem(KEY), null);
  assert.equal(mount.hidden, true);
});

test("nothing shows when the lists are empty", () => {
  const { main } = homePage(new Storage());
  const mount = main.querySelector("div");
  assert.equal(mount.hidden, true);
  assert.equal(mount.children.length, 0);
});

test("tampered or malformed entries are dropped, never rendered", () => {
  const bad = [
    { ...secret(), path: "https://evil.example/" },
    { ...secret(), path: "//evil.example/v/kv-test/secrets/x" },
    { ...secret(), path: "javascript:alert(1)" },
    { ...secret(), path: "/v/kv-test/secrets/other" },
    { ...secret(), path: "/v/kv-test/secrets/db-password\\x" },
    { ...secret(), path: "/v/kv-test/secrets/db-password\n" },
    { ...secret("<img src=x onerror=alert(1)>") },
    { ...secret("x/../../auth"), path: "/v/kv-test/secrets/x/../../auth" },
    { ...secret(), vault: "kv--test", path: "/v/kv--test/secrets/db-password" },
    { ...secret(), kind: "script" },
    { ...vaultEntry(), name: "other" },
    "a string",
    null,
  ];
  const storage = new Storage({ [KEY]: JSON.stringify({ pinned: bad, recent: [secret("ok")] }) });
  const { main } = homePage(storage);
  assert.deepEqual(
    all(main, "a").map((a) => a.getAttribute("href")),
    ["/v/kv-test/secrets/ok"],
  );
  assert.equal(all(main, "h2").length, 1);
});

test("unreadable storage is ignored", () => {
  for (const raw of ["not json", "[]", "42", JSON.stringify({ pinned: "x", recent: {} })]) {
    const { main } = homePage(new Storage({ [KEY]: raw }));
    assert.equal(main.querySelector("div").hidden, true, raw);
  }
});

test("a browser that refuses storage gets no star and no lists, and nothing throws", () => {
  for (const storage of [new Storage({}, { refuse: true }), new Storage({}, { full: true }), undefined]) {
    const item = itemPage(storage);
    assert.equal(all(item.main, "button").length, 0);
    const home = homePage(storage);
    assert.equal(home.main.querySelector("div").hidden, true);
  }
});

test("a full quota leaves the star as it was", () => {
  const storage = new Storage();
  const { main } = itemPage(storage);
  storage.full = true;
  const button = all(main, "button")[0];
  button.click();
  assert.equal(button.getAttribute("aria-pressed"), "false");
});

test("signing out clears the list, and so does the signed-out page", () => {
  const data = JSON.stringify({ pinned: [secret()], recent: [secret()] });
  const storage = new Storage({ [KEY]: data });
  const { body } = page(
    (h) => [h("form", { method: "post", action: "/auth/sign-out", "data-pins-clear": "" })],
    { script: "pins.js", storage },
  );
  body.querySelector("form").dispatch("submit");
  assert.equal(storage.getItem(KEY), null);

  const again = new Storage({ [KEY]: data });
  page((h) => [h("div", { "data-pins-signed-out": "" })], { script: "pins.js", storage: again });
  assert.equal(again.getItem(KEY), null);
});
