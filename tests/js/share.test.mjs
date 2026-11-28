// Tests for static/share.js, the share picker (#286). Run with
// `node --test tests/js/*.test.mjs`. No packages.

import test from "node:test";
import assert from "node:assert/strict";
import { page, settle } from "./stubs.mjs";

const BLAIR = "aaaaaaaa-0000-0000-0000-000000000002";

// The Share form, as templates/secrets/share.html renders it.
function form(fetch, url = "/v/kv-test/share/people") {
  return page(
    (h) => [
      h("form", { "data-share-picker": url }, [
        h("input", { type: "hidden", name: "principal", "data-share-principal": "" }),
        h("input", { id: "who", name: "who", "data-share-query": "" }),
        h("p", { "data-share-status": "" }),
        h("ul", { "data-share-results": "", hidden: true }),
      ]),
    ],
    { script: "share.js", fetch },
  );
}

const answer = (body) => () => Promise.resolve({ status: 200, json: () => Promise.resolve(body) });
const parts = (main) => ({
  input: main.querySelector("input[data-share-query]"),
  hidden: main.querySelector("input[data-share-principal]"),
  list: main.querySelector("ul[data-share-results]"),
  status: main.querySelector("p[data-share-status]"),
});

function type(main, clock, text) {
  const { input } = parts(main);
  input.value = text;
  input.dispatch("input");
  clock.advance(400);
}

test("searches after a pause, with the query encoded, and shows results as text", async () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const { main, clock, fetches } = form(
    answer({ results: [{ id: BLAIR, name: hostile, mail: "blair@example.com", upn: "blair@example.com", type: "Person" }] }),
  );
  type(main, clock, 'bl"a&b');
  await settle();
  assert.equal(fetches.length, 1);
  assert.equal(fetches[0].url, "/v/kv-test/share/people?q=bl%22a%26b");
  assert.equal(fetches[0].opts.credentials, "same-origin");
  const { list, hidden, input, status } = parts(main);
  assert.equal(list.hidden, false);
  const [button] = list.querySelectorAll("button");
  assert.equal(button.type, "button");
  assert.ok(button.textContent.startsWith(hostile), "shown as text, not markup");
  assert.equal(button.querySelectorAll("img").length, 0);
  button.click();
  assert.equal(hidden.value, BLAIR);
  assert.equal(input.value, hostile);
  assert.equal(list.hidden, true);
  assert.match(status.textContent, /Picked/);
});

test("a pick cancels the search still waiting, so the list stays closed", async () => {
  const { main, clock, fetches } = form(
    answer({ results: [{ id: BLAIR, name: "Blair", mail: "blair@example.com", upn: "blair@example.com", type: "Person" }] }),
  );
  type(main, clock, "bla");
  await settle();
  const { input, list, hidden, status } = parts(main);
  input.value = "blai";
  input.dispatch("input");
  list.querySelectorAll("button")[0].click();
  clock.advance(400);
  await settle();
  assert.equal(fetches.length, 1, "the waiting search never ran");
  assert.equal(hidden.value, BLAIR);
  assert.equal(list.hidden, true);
  assert.match(status.textContent, /Picked Blair/);
});

test("short queries, emails and object IDs don't search, and typing drops a pick", async () => {
  const { main, clock, fetches } = form(answer({ results: [] }));
  const { hidden } = parts(main);
  hidden.value = BLAIR;
  for (const q of ["b", "blair@example.com", BLAIR]) type(main, clock, q);
  await settle();
  assert.equal(fetches.length, 0);
  assert.equal(hidden.value, "", "a stale pick is never sent");
});

test("rows that aren't the five expected fields in their shapes are dropped", async () => {
  const { main, clock } = form(
    answer({
      results: [
        { id: "not-a-guid", name: "x", type: "Person" },
        { id: BLAIR, name: "ok", type: "Admin" },
        { id: BLAIR, name: "Blair", mail: 5, upn: null, type: "Group", extra: "<b>" },
      ],
    }),
  );
  type(main, clock, "bl");
  await settle();
  const buttons = parts(main).list.querySelectorAll("button");
  assert.equal(buttons.length, 1);
  assert.ok(buttons[0].textContent.startsWith("Blair (Group)"));
});

test("the server's message is shown, and a failed search says what to do", async () => {
  let { main, clock } = form(answer({ results: [], problem: "consent", message: "Needs User.ReadBasic.All" }));
  type(main, clock, "bl");
  await settle();
  assert.equal(parts(main).status.textContent, "Needs User.ReadBasic.All");
  ({ main, clock } = form(() => Promise.reject(new Error("offline"))));
  type(main, clock, "bl");
  await settle();
  assert.match(parts(main).status.textContent, /email address or object ID/);
});

test("does nothing for an endpoint that isn't Keyring's own path", async () => {
  for (const url of ["https://evil.example/x", "//evil.example/v/kv/share/people", "/v/kv/share/people?x=1"]) {
    const { main, clock, fetches } = form(answer({ results: [] }), url);
    type(main, clock, "blair");
    await settle();
    assert.equal(fetches.length, 0, url);
  }
});
