// Tests for static/app.js. Run with `node --test tests/js/`. No packages:
// the browser parts it touches are hand-written stubs in stubs.mjs.

import test from "node:test";
import assert from "node:assert/strict";
import { page, settle, Clipboard } from "./stubs.mjs";

const SECRET = "s3cret-value";

// The reveal panel as templates/secrets/revealed.html renders it.
function revealPanel(h, { use = false } = {}) {
  return [
    h("section", { "data-reveal": "", "data-clear-after": "30" }, [
      h("textarea", { id: "secret-value", "data-secret-value": "", value: SECRET }),
      h("div", { class: "actions" }, [
        h("button", { "data-copy": "secret-value", hidden: true, text: "Copy" }),
        h("button", { "data-extend": "", hidden: true, text: "Show for longer" }),
        ...(use ? [h("button", { "data-use-value": "", hidden: true, text: "Use this value" })] : []),
        h("a", { href: "/secrets/db", "data-hide-link": "" }),
        h("span", { role: "status", "data-copy-status": "" }),
      ]),
      h("p", { "data-countdown": "", hidden: true }, [
        h("span", { "data-countdown-secs": "", text: "30" }),
        h("span", { role: "status", "data-countdown-announce": "" }),
      ]),
    ]),
  ];
}

function reveal(opts = {}) {
  const p = page((h) => revealPanel(h, opts), opts);
  const q = (s) => p.main.querySelector(s);
  return {
    ...p,
    field: q("[data-secret-value]"),
    copy: q("[data-copy]"),
    extend: q("[data-extend]"),
    use: q("[data-use-value]"),
    hideLink: q("[data-hide-link]"),
    status: q("[data-copy-status]"),
    secs: q("[data-countdown-secs]"),
    announce: q("[data-countdown-announce]"),
  };
}

// Let a `say()` land: it empties the region, then fills it 100 ms later.
async function spoken(p) {
  await settle();
  p.clock.advance(150);
  await settle();
}

test("copy writes the value and offers the buttons the browser can use", async () => {
  const p = reveal();
  assert.equal(p.copy.hidden, false);
  assert.equal(p.extend.hidden, false);
  p.copy.click();
  await spoken(p);
  assert.equal(p.clipboard.text, SECRET);
  assert.match(p.status.textContent, /Keyring will try to clear the clipboard in 30 seconds/);
});

test("Copy stays hidden when the browser has no clipboard", () => {
  const p = reveal({ clipboard: {} });
  assert.equal(p.copy.hidden, true);
});

test("the clipboard is cleared when it still holds the value", async () => {
  const p = reveal();
  p.copy.click();
  await settle();
  p.hideLink.click();
  await spoken(p);
  assert.equal(p.clipboard.text, "");
  assert.deepEqual(p.clipboard.writes, [SECRET, ""]);
  assert.equal(p.status.textContent, "Value hidden. Clipboard cleared.");
});

test("the clipboard is left alone when the person has copied something else", async () => {
  const p = reveal();
  p.copy.click();
  await settle();
  p.clipboard.text = "something they copied later";
  p.hideLink.click();
  await spoken(p);
  assert.equal(p.clipboard.text, "something they copied later");
  assert.deepEqual(p.clipboard.writes, [SECRET]);
  assert.equal(p.status.textContent, "Value hidden.");
});

test("the clipboard is overwritten when it can't be read", async () => {
  for (const clipboard of [new Clipboard({ canRead: false }), Object.assign(new Clipboard(), { refuseReads: true })]) {
    const p = reveal({ clipboard });
    p.copy.click();
    await settle();
    p.hideLink.click();
    await spoken(p);
    assert.equal(p.clipboard.text, "");
    assert.equal(p.status.textContent, "Value hidden. Clipboard cleared.");
  }
});

test("Hide clears the clipboard before it leaves the page", async () => {
  const p = reveal();
  p.copy.click();
  await settle();
  const event = p.hideLink.click();
  assert.equal(event.defaultPrevented, true, "waits for the clear");
  await settle();
  assert.equal(p.clipboard.text, "");
  assert.deepEqual(p.assigned, ["/secrets/db"]);
  p.clock.advance(2000);
  assert.deepEqual(p.assigned, ["/secrets/db"], "leaves once");
});

// The rest of a reveal page: Back above the panel, plus the side nav and the
// sign-out form from templates/base.html.
function revealPage(h) {
  return [
    h("a", { href: "/secrets/db", id: "back", text: "Back to db" }),
    h("a", { href: "/expiry", id: "nav" }),
    h("a", { href: "/docs", id: "new-tab", target: "_blank" }),
    h("a", { href: "#main", id: "skip" }),
    h("form", { method: "post", action: "/auth/sign-out", id: "sign-out" }),
    ...revealPanel(h),
  ];
}

function revealWithShell() {
  const p = page(revealPage);
  const q = (s) => p.main.querySelector(s);
  const byId = (id) => [...p.main.querySelectorAll("a"), ...p.main.querySelectorAll("form")].find((e) => e.id === id);
  const form = byId("sign-out");
  form.submitted = 0;
  form.submit = () => {
    form.submitted += 1;
  };
  return { ...p, copy: q("[data-copy]"), form, link: byId };
}

test("Back and the side nav clear the clipboard before they leave", async () => {
  for (const id of ["back", "nav"]) {
    const p = revealWithShell();
    p.copy.click();
    await settle();
    const event = p.link(id).click();
    assert.equal(event.defaultPrevented, true, `${id} waits for the clear`);
    await settle();
    assert.equal(p.clipboard.text, "", id);
    assert.deepEqual(p.assigned, [p.link(id).href], id);
    p.clock.advance(2000);
    assert.equal(p.assigned.length, 1, `${id} leaves once`);
  }
});

test("a stalled clear still leaves after a second and a half", async () => {
  const p = revealWithShell();
  p.copy.click();
  await settle();
  p.clipboard.readText = () => new Promise(() => {}); // a paste prompt nobody answers
  p.link("back").click();
  await settle();
  assert.deepEqual(p.assigned, []);
  p.clock.advance(1500);
  assert.deepEqual(p.assigned, ["/secrets/db"]);
});

test("Sign out clears the clipboard before it submits", async () => {
  const p = revealWithShell();
  p.copy.click();
  await settle();
  const event = p.form.dispatch("submit");
  assert.equal(event.defaultPrevented, true);
  await settle();
  assert.equal(p.clipboard.text, "");
  assert.equal(p.form.submitted, 1);
  p.clock.advance(2000);
  assert.equal(p.form.submitted, 1, "submits once");
});

test("leaving with nothing copied, or into a new tab, isn't held up", async () => {
  const p = revealWithShell();
  assert.equal(p.link("back").click().defaultPrevented, false, "nothing copied");
  assert.equal(p.form.dispatch("submit").defaultPrevented, false, "nothing copied");
  p.copy.click();
  await settle();
  assert.equal(p.link("new-tab").click().defaultPrevented, false, "target=_blank");
  assert.equal(p.link("skip").click().defaultPrevented, false, "same-page jump");
  assert.equal(p.link("back").dispatch("click", { ctrlKey: true }).defaultPrevented, false, "ctrl-click");
  assert.equal(p.link("back").dispatch("click", { button: 1 }).defaultPrevented, false, "middle click");
  assert.equal(p.clipboard.text, SECRET, "the value stays on the page and the clipboard");
});

test("Hide with nothing copied follows the link straight away", () => {
  const p = reveal();
  const event = p.hideLink.click();
  assert.equal(event.defaultPrevented, false);
  assert.equal(p.clipboard.writes.length, 0);
});

test("hiding removes the value from the page, not just the box", async () => {
  const p = reveal();
  p.hideLink.click();
  await settle();
  assert.equal(p.field.value, "");
  assert.equal(p.field.textContent, "");
  assert.equal(p.field.defaultValue, "");
  assert.equal(p.field.hidden, true);
  assert.equal(p.copy.hidden, true);
  assert.equal(p.extend.hidden, true);
});

test("the deadline holds when a background tab slows the timer", async () => {
  const p = reveal();
  p.copy.click();
  await settle();
  // 40 seconds pass but the throttled timer never fires.
  p.clock.skip(40_000);
  assert.equal(p.field.hidden, false);
  // The next tick, however late, sees the deadline has gone.
  p.clock.advance(1000);
  await spoken(p);
  assert.equal(p.field.hidden, true);
  assert.equal(p.clipboard.text, "");
});

test("the countdown hides the value at 30 seconds and warns at 20", async () => {
  const p = reveal();
  await spoken(p);
  assert.match(p.announce.textContent, /Shown for 30 seconds, then hidden\. Choose Show for longer/);
  p.clock.advance(9_000);
  assert.equal(p.secs.textContent, "21");
  p.clock.advance(1_000);
  await spoken(p);
  assert.equal(p.announce.textContent, "Hiding in 20 seconds. Choose Show for longer to keep it.");
  p.clock.advance(18_000);
  assert.equal(p.field.hidden, false);
  p.clock.advance(2_000);
  await settle();
  assert.equal(p.field.hidden, true);
  assert.equal(p.secs.textContent, "0");
});

test("Show for longer moves the deadline and warns again", async () => {
  const p = reveal();
  p.clock.advance(25_000);
  p.extend.click();
  await spoken(p);
  assert.equal(p.secs.textContent, "30");
  assert.equal(p.announce.textContent, "Shown for another 30 seconds.");
  p.clock.advance(20_000);
  assert.equal(p.field.hidden, false);
  await spoken(p);
  assert.match(p.announce.textContent, /^Hiding in \d+ seconds/);
  p.clock.advance(15_000);
  assert.equal(p.field.hidden, true);
});

test("switching tabs does not hide the value, leaving the page does", async () => {
  const p = reveal();
  p.doc.visibilityState = "hidden";
  p.doc.dispatch("visibilitychange");
  assert.equal(p.field.hidden, false);
  p.win.dispatch("pagehide");
  await settle();
  assert.equal(p.field.hidden, true);
});

test("a clear refused in a background tab is tried again on return", async () => {
  const p = reveal();
  p.copy.click();
  await settle();
  p.clipboard.refuseWrites = true;
  p.clock.advance(31_000);
  await spoken(p);
  assert.equal(p.field.hidden, true);
  assert.equal(p.clipboard.text, SECRET);
  assert.match(p.status.textContent, /couldn't clear the clipboard yet/);
  p.clipboard.refuseWrites = false;
  p.win.dispatch("focus");
  await spoken(p);
  assert.equal(p.clipboard.text, "");
  assert.equal(p.status.textContent, "Value hidden. Clipboard cleared.");
  // Nothing left to do on later visits.
  p.win.dispatch("focus");
  await settle();
  assert.deepEqual(p.clipboard.writes, [SECRET, ""]);
});

test("coming back after the deadline hides the value at once", async () => {
  const p = reveal();
  p.clock.skip(60_000);
  p.doc.dispatch("visibilitychange");
  assert.equal(p.field.hidden, true);
});

test("the copy status is announced again on a second copy", async () => {
  const p = reveal();
  p.copy.click();
  await spoken(p);
  p.copy.click();
  await spoken(p);
  const msg = "Copied. Keyring will try to clear the clipboard in 30 seconds.";
  // Emptied between the two, so a screen reader hears it twice.
  assert.deepEqual(p.status.texts, ["", msg, "", msg]);
});

test("a failed copy says so", async () => {
  const p = reveal();
  p.clipboard.refuseWrites = true;
  p.copy.click();
  await spoken(p);
  assert.equal(p.status.textContent, "Couldn't copy. Select the value and copy it yourself.");
});

function opener(withForm) {
  const target = { value: "" };
  return {
    target,
    win: {
      closed: false,
      location: { origin: "https://keyring.example" },
      document: { getElementById: (id) => (withForm && id === "value" ? target : null) },
    },
  };
}

test("Use this value fills the secret form and keeps its message", async () => {
  const o = opener(true);
  const p = reveal({ use: true, opener: o.win });
  assert.equal(p.use.hidden, false);
  p.use.click();
  await spoken(p);
  assert.equal(o.target.value, SECRET);
  assert.equal(p.status.textContent, "Added to the secret form.");
  assert.equal(p.win.closed, true);
});

test("Use this value explains when the secret form has gone", async () => {
  const o = opener(false);
  const p = reveal({ use: true, opener: o.win });
  p.use.click();
  await spoken(p);
  assert.equal(p.status.textContent, "The secret form isn't open any more. Copy the value instead.");
  assert.equal(p.field.hidden, false);
  assert.equal(p.win.closed, false);
});

test("Use this value stays hidden without a same-origin opener", () => {
  const p = reveal({ use: true });
  assert.equal(p.use.hidden, true);
  const other = { location: { origin: "https://elsewhere.example" } };
  assert.equal(reveal({ use: true, opener: other }).use.hidden, true);
});

// The key page's two plain copy buttons, sharing one status line.
function keyPage(opts) {
  return page(
    (h) => [
      h("textarea", { id: "public-pem", value: "PEM TEXT" }),
      h("button", { "data-copy-plain": "public-pem", hidden: true, text: "Copy PEM" }),
      h("textarea", { id: "public-jwk", value: "{}" }),
      h("button", { "data-copy-plain": "public-jwk", hidden: true, text: "Copy JWK" }),
      h("span", { role: "status", "data-copy-plain-status": "" }),
    ],
    opts,
  );
}

test("plain copy says what was copied, and when it failed", async () => {
  const p = keyPage();
  const [pem, jwk] = p.main.querySelectorAll("[data-copy-plain]");
  const status = p.main.querySelector("[data-copy-plain-status]");
  assert.equal(pem.hidden, false);
  pem.click();
  await spoken(p);
  assert.equal(status.textContent, "Copied the PEM.");
  assert.equal(p.clipboard.text, "PEM TEXT");
  jwk.click();
  await spoken(p);
  assert.equal(status.textContent, "Copied the JWK.");
  p.clipboard.refuseWrites = true;
  jwk.click();
  await spoken(p);
  assert.equal(status.textContent, "Couldn't copy the JWK. Select it and copy it yourself.");
});

// A list page as templates/secrets/list.html renders it.
function listPage(names, { paged = false } = {}) {
  return page((h) => [
    h("form", { "data-live-filter": "t" }, [h("input", { type: "search" })]),
    h("div", { class: "table-wrap" }, [
      h("table", { id: "t" }, [
        h("caption", { text: "Secrets in kv-test" }),
        h("tbody", {}, names.map((n) => h("tr", { "data-filter-text": n }))),
      ]),
    ]),
    h("p", { "data-live-filter-empty": "", role: "status", hidden: true, text: "No secrets on this page match." }),
    ...(paged ? [h("nav", { class: "pager" })] : []),
  ]);
}

function type(p, text) {
  const input = p.main.querySelector('input[type="search"]');
  input.value = text;
  input.dispatch("input");
}

test("the live filter hides rows at once and speaks the count after a pause", () => {
  const p = listPage(["db-password", "db-user", "api-key"]);
  const count = p.main.querySelector(".visually-hidden");
  const rows = p.main.querySelectorAll("tr");
  type(p, "d");
  type(p, "db");
  assert.deepEqual(rows.map((r) => r.hidden), [false, false, true]);
  assert.equal(count.textContent, "");
  p.clock.advance(300);
  assert.equal(count.textContent, "2 of 3 secrets on this page match.");
  assert.deepEqual(count.texts, ["2 of 3 secrets on this page match."], "spoken once");
});

test("the live filter points at the server search when there are more pages", () => {
  const p = listPage(["db-password", "api-key"], { paged: true });
  type(p, "api");
  p.clock.advance(300);
  assert.equal(
    p.main.querySelector(".visually-hidden").textContent,
    "1 of 2 secrets on this page matches. Press Filter to search every page.",
  );
});

test("at zero only the visible message speaks", () => {
  const p = listPage(["db-password"]);
  const count = p.main.querySelector(".visually-hidden");
  const empty = p.main.querySelector("[data-live-filter-empty]");
  assert.equal(empty.textContent, "", "blank until needed");
  type(p, "zzz");
  assert.equal(empty.hidden, false);
  p.clock.advance(300);
  assert.equal(count.textContent, "");
  assert.equal(empty.textContent, "No secrets on this page match.");
  type(p, "");
  p.clock.advance(300);
  assert.equal(empty.hidden, true);
  assert.equal(empty.textContent, "");
});

// The idle notice.
function idle(opts = {}) {
  return page(() => [], { body: { "data-idle-seconds": "3600" }, ...opts });
}
const notice = (p) => p.main.querySelector(".idle-notice");
const stay = (p) => notice(p).querySelector("button");

test("no idle notice without the attribute, or with it empty", () => {
  assert.equal(page(() => []).main.querySelector(".idle-status"), null);
  assert.equal(page(() => [], { body: { "data-idle-seconds": "" } }).main.querySelector(".idle-status"), null);
});

test("the idle notice appears five minutes before the limit", async () => {
  const p = idle();
  const region = p.main.querySelector(".idle-status");
  assert.equal(region.getAttribute("role"), "status");
  assert.equal(notice(p).hidden, true);
  p.clock.advance(54 * 60_000);
  assert.equal(notice(p).hidden, true);
  p.clock.advance(60_000 + 15_000);
  await spoken(p);
  assert.equal(notice(p).hidden, false);
  assert.equal(stay(p).hidden, false);
  assert.equal(stay(p).textContent, "Stay signed in");
  assert.match(notice(p).querySelector("p").textContent, /signed out in about 5 minutes/);
});

test("Stay signed in calls keepalive and resets the timer", async () => {
  const p = idle();
  p.clock.advance(57 * 60_000);
  stay(p).click();
  await settle();
  assert.equal(p.fetches.length, 1);
  assert.equal(p.fetches[0].url, "/auth/keepalive");
  assert.equal(p.fetches[0].opts.credentials, "same-origin");
  assert.equal(notice(p).hidden, true);
  assert.equal(p.doc.activeElement.textContent, "You're still signed in.");
  // A full hour from the keepalive, not from page load.
  p.clock.advance(54 * 60_000);
  assert.equal(notice(p).hidden, true);
  p.clock.advance(2 * 60_000);
  assert.equal(notice(p).hidden, false);
});

test("key presses do not reset the idle timer", () => {
  const p = idle();
  p.clock.advance(56 * 60_000);
  p.doc.dispatch("keydown");
  p.body.dispatch("keydown");
  p.clock.advance(15_000);
  assert.equal(notice(p).hidden, false);
});

test("when the limit passes the notice says the person is signed out", async () => {
  const p = idle();
  p.clock.advance(61 * 60_000);
  await spoken(p);
  assert.equal(notice(p).hidden, false);
  assert.equal(stay(p).hidden, true);
  assert.match(notice(p).querySelector("p").textContent, /You have been signed out/);
});

test("a background tab that comes back late shows the signed out message", async () => {
  const p = idle();
  p.clock.skip(2 * 60 * 60_000);
  p.doc.dispatch("visibilitychange");
  await spoken(p);
  assert.equal(stay(p).hidden, true);
  assert.match(notice(p).querySelector("p").textContent, /You have been signed out/);
});

test("a keepalive that finds the session gone says so", async () => {
  const p = idle({ fetch: () => Promise.resolve({ status: 200, redirected: true }) });
  p.clock.advance(57 * 60_000);
  stay(p).click();
  await spoken(p);
  assert.equal(stay(p).hidden, true);
  assert.match(notice(p).querySelector("p").textContent, /You have been signed out/);
});

test("a keepalive that can't reach Keyring can be tried again", async () => {
  const p = idle({ fetch: () => Promise.reject(new Error("offline")) });
  p.clock.advance(57 * 60_000);
  stay(p).click();
  await spoken(p);
  assert.equal(stay(p).hidden, false);
  assert.match(notice(p).querySelector("p").textContent, /Couldn't reach Keyring/);
});

// Table wrappers as the _ui.html table_wrap macro renders them.
function tables(widths) {
  return page((h) =>
    widths.map(([scrollWidth, clientWidth]) =>
      h("div", { class: "table-wrap", role: "region", tabindex: "0", "data-table-wrap": "", scrollWidth, clientWidth }),
    ),
  );
}

test("a table wrapper is a tab stop only while its table overflows", () => {
  const p = tables([[900, 400], [300, 400]]);
  const [wide, narrow] = p.main.querySelectorAll("[data-table-wrap]");
  assert.equal(wide.getAttribute("tabindex"), "0");
  assert.equal(narrow.hasAttribute("tabindex"), false);
});

test("the tab stop follows the table when the window is resized", () => {
  const p = tables([[300, 400]]);
  const wrap = p.main.querySelector("[data-table-wrap]");
  assert.equal(wrap.hasAttribute("tabindex"), false);
  wrap.clientWidth = 200;
  p.win.dispatch("resize");
  assert.equal(wrap.hasAttribute("tabindex"), false, "waits for resizing to stop");
  p.clock.advance(200);
  assert.equal(wrap.getAttribute("tabindex"), "0");
  wrap.clientWidth = 600;
  p.win.dispatch("resize");
  p.clock.advance(200);
  assert.equal(wrap.hasAttribute("tabindex"), false);
});

test("a flash message takes focus when there is no error summary", () => {
  const p = page((h) => [h("p", { tabindex: "-1", "data-flash": "", text: "Saved." })]);
  assert.equal(p.doc.activeElement, p.main.querySelector("[data-flash]"));
});

test("an error summary takes focus before a flash message", () => {
  const p = page((h) => [
    h("p", { tabindex: "-1", "data-flash": "", text: "Saved." }),
    h("div", { tabindex: "-1", "data-error-summary": "" }),
  ]);
  assert.equal(p.doc.activeElement, p.main.querySelector("[data-error-summary]"));
});
