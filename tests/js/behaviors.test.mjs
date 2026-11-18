// Tests for static/behaviors.js: the More menu, the combobox model, and
// focus recovery. Run with `node --test tests/js/*.test.mjs`. No packages.

import test from "node:test";
import assert from "node:assert/strict";
import { page, settle } from "./stubs.mjs";

const key = (el, k, extra = {}) => el.dispatch("keydown", { key: k, ...extra });
// The stub doesn't bubble, so a key on a menu item is sent to the menu with
// the item as its target, as it would arrive there in a browser.
const menuKey = (box) => (el, k) => box.dispatch("keydown", { key: k, target: el });

// A command bar's More menu, as templates/secrets/detail.html renders it,
// with a disabled item that must be skipped.
function menuPage() {
  const p = page(
    (h) => [
      h("a", { id: "before", href: "/x" }),
      h("details", { class: "menu", "data-behavior": "menu" }, [
        h("summary", { class: "cmd", text: "More" }),
        h("ul", { class: "menu-list" }, [
          h("li", {}, [h("a", { class: "menu-item", href: "/copy", text: "Copy to another vault" })]),
          h("li", {}, [h("a", { class: "menu-item", href: "/disable", text: "Disable" })]),
          h("li", {}, [h("button", { class: "menu-item", disabled: "", text: "Dump" })]),
          h("li", { class: "menu-sep", role: "presentation" }),
          h("li", {}, [h("a", { class: "menu-item danger", href: "/delete", text: "Delete" })]),
          h("li", {}, [h("a", { class: "menu-item", href: "/details", text: "Details" })]),
        ]),
      ]),
      h("a", { id: "after", href: "/y" }),
    ],
    { script: "behaviors.js" },
  );
  const box = p.main.querySelector("details");
  const items = box.querySelectorAll("a");
  return { ...p, box, summary: box.querySelector("summary"), items };
}

test("a menu says whether it is open, and opening focuses the first item", () => {
  const { box, summary, items, doc } = menuPage();
  assert.equal(summary.getAttribute("aria-expanded"), "false");
  assert.equal(box.getAttribute("role"), null, "a disclosure keeps native semantics");
  box.open = true;
  assert.equal(summary.getAttribute("aria-expanded"), "true");
  assert.equal(doc.activeElement, items[0]);
});

test("arrow keys, Home and End rove between items and skip disabled ones", () => {
  const { box, summary, items, doc } = menuPage();
  const key = menuKey(box);
  summary.focus();
  key(summary, "ArrowDown");
  assert.ok(box.open, "Arrow Down on the summary opens it");
  assert.equal(doc.activeElement, items[0]);
  key(items[0], "ArrowDown");
  key(items[1], "ArrowDown");
  assert.equal(doc.activeElement, items[2], "the disabled button is skipped");
  key(items[2], "ArrowDown");
  key(items[3], "ArrowDown");
  assert.equal(doc.activeElement, items[0], "wraps round");
  key(items[0], "ArrowUp");
  assert.equal(doc.activeElement, items[3]);
  key(items[3], "Home");
  assert.equal(doc.activeElement, items[0]);
  const end = key(items[0], "End");
  assert.equal(doc.activeElement, items[3]);
  assert.ok(end.defaultPrevented, "the page doesn't scroll");
});

test("typing letters jumps to an item by its first letters", () => {
  const { box, items, doc, clock } = menuPage();
  const key = menuKey(box);
  box.open = true;
  key(items[0], "d");
  assert.equal(doc.activeElement, items[1], "Disable");
  key(items[1], "d");
  assert.equal(doc.activeElement, items[2], "the same letter again steps on: Delete");
  clock.advance(1000);
  key(items[2], "d");
  key(items[3], "e");
  key(items[3], "t");
  assert.equal(doc.activeElement, items[3], "Det matches Details");
  clock.advance(1000);
  key(items[3], "z");
  assert.equal(doc.activeElement, items[3], "no match leaves focus where it is");
});

test("Escape closes the menu and returns focus to the summary", () => {
  const { box, summary, items, doc } = menuPage();
  const key = menuKey(box);
  box.open = true;
  const e = key(items[1], "Escape");
  assert.ok(e.defaultPrevented);
  assert.equal(box.open, false);
  assert.equal(summary.getAttribute("aria-expanded"), "false");
  assert.equal(doc.activeElement, summary);
});

test("a click outside or a Tab away closes the menu", () => {
  const { box, items, main, doc } = menuPage();
  box.open = true;
  items[0].dispatch("click");
  assert.ok(box.open, "a click inside keeps it open");
  doc.dispatch("click", { target: main.querySelector("a") });
  assert.equal(box.open, false);
  box.open = true;
  box.dispatch("focusout", { target: items[0], relatedTarget: items[1] });
  assert.ok(box.open, "moving within keeps it open");
  box.dispatch("focusout", { target: items[3], relatedTarget: main.querySelector("a[id=\"after\"]") });
  assert.equal(box.open, false);
});

// A combobox over a list the caller fills, as share.js uses it.
function comboPage() {
  const p = page(
    (h) => [
      h("input", { id: "who" }),
      h("ul", { hidden: true }),
    ],
    { script: "behaviors.js" },
  );
  const input = p.main.querySelector("input");
  const box = p.main.querySelector("ul");
  const chosen = [];
  let cleared = 0;
  const combo = p.win.KeyringBehaviors.combobox(input, box, {
    choose: (o) => chosen.push(o.textContent),
    clear: () => cleared++,
  });
  const fill = (names) => {
    box.children = [];
    names.forEach((n, i) => box.appendChild(p.h("li", {}, [p.h("button", { role: "option", id: `o${i}`, text: n })])));
    combo.refresh();
  };
  return { ...p, input, box, combo, fill, chosen, cleared: () => cleared };
}

test("combobox roles and states are set on the input and list", () => {
  const { input, box } = comboPage();
  assert.equal(input.getAttribute("role"), "combobox");
  assert.equal(input.getAttribute("aria-controls"), box.id);
  assert.equal(input.getAttribute("aria-expanded"), "false");
  assert.equal(box.getAttribute("role"), "listbox");
});

test("arrow keys move the highlight, named by aria-activedescendant, and Enter picks", () => {
  const { input, box, fill, chosen } = comboPage();
  fill(["Alex", "Blair", "Casey"]);
  assert.equal(box.hidden, false);
  assert.equal(input.getAttribute("aria-expanded"), "true");
  assert.equal(input.getAttribute("aria-activedescendant"), null, "nothing highlighted yet");
  key(input, "ArrowDown");
  assert.equal(input.getAttribute("aria-activedescendant"), "o0");
  key(input, "ArrowDown");
  assert.equal(input.getAttribute("aria-activedescendant"), "o1");
  assert.equal(box.querySelector("button[id=\"o1\"]").getAttribute("aria-selected"), "true");
  assert.equal(box.querySelector("button[id=\"o0\"]").getAttribute("aria-selected"), "false");
  key(input, "ArrowUp");
  key(input, "ArrowUp");
  assert.equal(input.getAttribute("aria-activedescendant"), "o2", "wraps round");
  const e = key(input, "Enter");
  assert.ok(e.defaultPrevented, "Enter picks rather than submitting the form");
  assert.deepEqual(chosen, ["Casey"]);
});

test("Enter with nothing highlighted is left to the form", () => {
  const { input, fill, chosen } = comboPage();
  fill(["Alex"]);
  const e = key(input, "Enter");
  assert.equal(e.defaultPrevented, false);
  assert.deepEqual(chosen, []);
});

test("Escape closes the list, then clears the text", () => {
  const { input, box, fill, cleared } = comboPage();
  input.value = "bl";
  fill(["Blair"]);
  key(input, "ArrowDown");
  key(input, "Escape");
  assert.equal(box.hidden, true);
  assert.equal(input.getAttribute("aria-expanded"), "false");
  assert.equal(input.getAttribute("aria-activedescendant"), null);
  assert.equal(input.value, "bl", "the first Escape keeps the text");
  key(input, "Escape");
  assert.equal(input.value, "");
  assert.equal(cleared(), 1);
  key(input, "ArrowDown");
  assert.equal(box.hidden, false, "Arrow Down opens the list again");
  assert.equal(input.getAttribute("aria-activedescendant"), "o0");
});

test("focus recovery moves focus to the first fallback still on the page", () => {
  const { main, doc, win, h } = page((h) => [h("div", { id: "rows" })], { script: "behaviors.js" });
  const rows = main.querySelector("div");
  const a = h("button", { text: "A" });
  const b = h("button", { text: "B" });
  const gone = h("button", { text: "Gone" });
  const off = h("button", { text: "Off", disabled: "" });
  rows.appendChild(a);
  main.appendChild(b);
  main.appendChild(off);
  a.focus();
  const to = win.KeyringBehaviors.recover(rows, () => rows.removeChild(a), [gone, off, b]);
  assert.equal(to, b, "skips one that's gone and one that's disabled");
  assert.equal(doc.activeElement, b);
  // Focus that wasn't in the scope is left alone.
  b.focus();
  rows.appendChild(a);
  assert.equal(win.KeyringBehaviors.recover(rows, () => rows.removeChild(a), [a]), null);
  assert.equal(doc.activeElement, b);
  // Hidden counts as lost.
  rows.appendChild(a);
  a.focus();
  win.KeyringBehaviors.recover(rows, () => (rows.hidden = true), [b]);
  assert.equal(doc.activeElement, b);
});

test("removing a tag row moves focus to a neighbour's Remove", async () => {
  const { main, doc } = page(
    (h) => [
      h("fieldset", { "data-tag-rows": "", "data-tag-max": "40" }, [1, 2, 3].map((n) =>
        h("div", { class: "tag-row", "data-tag-row": "" }, [
          h("input", { id: `tag-name-${n}`, "data-tag-name": "" }),
          h("input", { id: `tag-value-${n}`, "data-tag-value": "" }),
        ]),
      )),
    ],
    { script: ["behaviors.js", "tags.js"] },
  );
  await settle();
  const removes = () => main.querySelectorAll("button.tag-remove");
  const [, second, third] = removes();
  second.focus();
  second.click();
  assert.equal(doc.activeElement, third, "the next row's Remove");
  third.click();
  assert.equal(doc.activeElement, removes()[0], "the last row falls back to the one before");
  removes()[0].click();
  assert.equal(doc.activeElement, main.querySelector("button.tag-add"));
});

test("the share picker is a combobox when behaviors.js is loaded", async () => {
  const BLAIR = "aaaaaaaa-0000-0000-0000-000000000002";
  const { main, clock } = page(
    (h) => [
      h("form", { "data-share-picker": "/v/kv-test/share/people" }, [
        h("input", { type: "hidden", "data-share-principal": "" }),
        h("input", { id: "who", "data-share-query": "" }),
        h("p", { "data-share-status": "" }),
        h("ul", { "data-share-results": "", hidden: true }),
      ]),
    ],
    {
      script: ["behaviors.js", "share.js"],
      fetch: () =>
        Promise.resolve({ json: () => Promise.resolve({ results: [{ id: BLAIR, name: "Blair", mail: "b@example.com", upn: "", type: "Person" }] }) }),
    },
  );
  const input = main.querySelector("input[data-share-query]");
  input.value = "bl";
  input.dispatch("input");
  clock.advance(400);
  await settle();
  assert.equal(input.getAttribute("aria-expanded"), "true");
  assert.equal(main.querySelector("p[data-share-status]").textContent, "1 found. Pick one.");
  const option = main.querySelector("ul[data-share-results]").querySelector("button");
  assert.equal(option.getAttribute("role"), "option");
  key(input, "ArrowDown");
  assert.equal(input.getAttribute("aria-activedescendant"), option.id);
  key(input, "Enter");
  assert.equal(main.querySelector("input[data-share-principal]").value, BLAIR);
  assert.equal(input.getAttribute("aria-expanded"), "false");
});
