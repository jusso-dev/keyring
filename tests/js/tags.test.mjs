// Tests for static/tags.js. Run with `node --test tests/js/`. No packages.

import test from "node:test";
import assert from "node:assert/strict";
import { page } from "./stubs.mjs";

// A tag field as templates/_ui.html renders it: rows, then the lists.
function form({ rows = [["env", "prod"], ["", ""]], max = 40 } = {}) {
  return page(
    (h) => [
      h(
        "fieldset",
        { class: "tag-rows", id: "tags", "data-tag-rows": "", "data-tag-max": String(max) },
        rows.map(([name, value], i) =>
          h("div", { class: "tag-row", "data-tag-row": "" }, [
            h("div", {}, [
              h("label", { for: `tag-name-${i + 1}`, text: `Tag ${i + 1} name` }),
              h("input", { id: `tag-name-${i + 1}`, name: `tag-name-${i + 1}`, value: name, list: "tag-names", "data-tag-name": "" }),
            ]),
            h("div", {}, [
              h("label", { for: `tag-value-${i + 1}`, text: `Tag ${i + 1} value` }),
              h("input", { id: `tag-value-${i + 1}`, name: `tag-value-${i + 1}`, value, list: "tag-values-any", "data-tag-value": "" }),
            ]),
          ]),
        ),
      ),
      h("datalist", { id: "tag-names" }),
      h("datalist", { id: "tag-values-any" }),
      h("datalist", { id: "tag-values-1", "data-tag-for": "env" }),
      h("datalist", { id: "tag-values-2", "data-tag-for": 'odd"] name' }),
    ],
    { script: "tags.js" },
  );
}

const rows = (main) => main.querySelectorAll("div[data-tag-row]");
const button = (main, cls) => main.querySelector(`button.${cls}`);

test("a row's value list follows its name, without a selector built from it", () => {
  const { main } = form();
  const [, second] = rows(main);
  const name = second.querySelector("input[data-tag-name]");
  const value = second.querySelector("input[data-tag-value]");
  name.value = "env";
  name.dispatch("input");
  assert.equal(value.getAttribute("list"), "tag-values-1");
  // Quotes and brackets in a name are compared as text.
  name.value = 'odd"] name';
  name.dispatch("change");
  assert.equal(value.getAttribute("list"), "tag-values-2");
  name.value = "unknown";
  name.dispatch("input");
  assert.equal(value.getAttribute("list"), "tag-values-any");
});

test("Add a tag makes a labelled row with the next number, and focuses it", () => {
  const { main, doc } = form();
  const add = button(main, "tag-add");
  assert.equal(add.textContent, "Add a tag");
  assert.equal(add.type, "button");
  add.click();
  const all = rows(main);
  assert.equal(all.length, 3);
  const name = all[2].querySelector("input[data-tag-name]");
  const value = all[2].querySelector("input[data-tag-value]");
  assert.equal(name.getAttribute("id"), "tag-name-3");
  assert.equal(name.getAttribute("name"), "tag-name-3");
  assert.equal(value.getAttribute("name"), "tag-value-3");
  assert.equal(value.getAttribute("list"), "tag-values-any");
  assert.equal(name.getAttribute("spellcheck"), "false");
  const labels = all[2].querySelectorAll("label").map((l) => [l.getAttribute("for"), l.textContent]);
  assert.deepEqual(labels, [
    ["tag-name-3", "Tag 3 name"],
    ["tag-value-3", "Tag 3 value"],
  ]);
  assert.equal(doc.activeElement, name);
  // The new row's value list follows its name too.
  name.value = "env";
  name.dispatch("input");
  assert.equal(value.getAttribute("list"), "tag-values-1");
});

test("Remove takes the row out, so its tag isn't posted", () => {
  const { main, doc } = form();
  const [first] = rows(main);
  const remove = first.querySelector("button");
  assert.equal(remove.textContent, "Remove tag 1");
  remove.click();
  assert.equal(rows(main).length, 1);
  assert.equal(main.querySelector('input[name="tag-name-1"]'), null);
  assert.equal(doc.activeElement, button(main, "tag-add"));
  // The lowest free number is used, so a gap at the limit can be filled.
  button(main, "tag-add").click();
  assert.ok(main.querySelector('input[name="tag-name-1"]'));
});

test("no more rows than the server reads", () => {
  const { main } = form({ max: 3 });
  const add = button(main, "tag-add");
  add.click();
  assert.equal(rows(main).length, 3);
  assert.equal(add.hidden, true);
  add.click();
  assert.equal(rows(main).length, 3);
});

test("removing a row at the limit lets Add a tag fill the gap", () => {
  const { main } = form({ rows: [["a", "1"], ["b", "2"], ["c", "3"]], max: 3 });
  const add = button(main, "tag-add");
  rows(main)[1].querySelector("button").click();
  assert.equal(add.hidden, false);
  add.click();
  assert.equal(rows(main).length, 3);
  assert.ok(main.querySelector('input[name="tag-name-2"]'), "the free number is used");
  assert.equal(add.hidden, true);
});

test("text goes in as text", () => {
  const { main } = form();
  button(main, "tag-add").click();
  for (const el of main.querySelectorAll("label")) {
    assert.ok(!el.textContent.includes("<"));
  }
});

test("a page without tag rows is left alone", () => {
  const { main } = page((h) => [h("p", { text: "nothing here" })], { script: "tags.js" });
  assert.equal(main.querySelectorAll("button").length, 0);
});
