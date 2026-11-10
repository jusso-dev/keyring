// Hand-written stand-ins for the parts of the browser that static/app.js
// uses: a few DOM elements, a clock with timers, the clipboard and fetch.
// No packages. Only as much as the script needs.

import fs from "node:fs";
import vm from "node:vm";

const SCRIPT = fs.readFileSync(new URL("../../static/app.js", import.meta.url), "utf8");

// One compound selector, such as `tr[data-filter-text]`, `.pager` or
// `input[type="search"]`.
function parseCompound(text) {
  const m = /^([a-z0-9]*)(?:\.([\w-]+))?(?:\[([\w-]+)(?:="([^"]*)")?\])?$/.exec(text);
  if (!m) {
    throw new Error(`stub selector not supported: ${text}`);
  }
  return { tag: m[1], cls: m[2], attr: m[3], val: m[4] };
}

function matches(el, c) {
  if (c.tag && el.tagName !== c.tag) return false;
  if (c.cls && !el.className.split(/\s+/).includes(c.cls)) return false;
  if (c.attr && !el.hasAttribute(c.attr)) return false;
  if (c.val !== undefined && el.getAttribute(c.attr) !== c.val) return false;
  return true;
}

export class Element {
  constructor(doc, tag, attrs = {}, children = []) {
    this.ownerDocument = doc;
    this.tagName = tag;
    this.attrs = new Map();
    this.children = [];
    this.parentNode = null;
    this.listeners = {};
    this.hidden = false;
    this.value = "";
    this.defaultValue = "";
    // Layout sizes, for the table wrapper. Tests set them by hand.
    this.scrollWidth = 0;
    this.clientWidth = 0;
    this.texts = []; // Every textContent set, in order, for live region checks.
    this._text = "";
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "hidden") this.hidden = !!v;
      else if (k === "scrollWidth" || k === "clientWidth") this[k] = v;
      else if (k === "text") this._text = v;
      else if (k === "value") {
        this.value = v;
        this.defaultValue = v;
        this._text = v;
      } else this.setAttribute(k, v);
    }
    for (const c of children) this.appendChild(c);
  }
  get className() {
    return this.getAttribute("class") || "";
  }
  set className(v) {
    this.setAttribute("class", v);
  }
  get id() {
    return this.getAttribute("id");
  }
  get href() {
    return this.getAttribute("href");
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this._text = String(v);
    this.children = [];
    this.texts.push(this._text);
  }
  getAttribute(k) {
    return this.attrs.has(k) ? this.attrs.get(k) : null;
  }
  setAttribute(k, v) {
    this.attrs.set(k, String(v));
  }
  hasAttribute(k) {
    return this.attrs.has(k);
  }
  removeAttribute(k) {
    this.attrs.delete(k);
  }
  appendChild(c) {
    return this.insertBefore(c, null);
  }
  insertBefore(c, ref) {
    if (c.parentNode) c.parentNode.children.splice(c.parentNode.children.indexOf(c), 1);
    c.parentNode = this;
    const i = ref ? this.children.indexOf(ref) : -1;
    if (i === -1) this.children.push(c);
    else this.children.splice(i, 0, c);
    return c;
  }
  get firstChild() {
    return this.children[0] || null;
  }
  get nextElementSibling() {
    if (!this.parentNode) return null;
    const sibs = this.parentNode.children;
    return sibs[sibs.indexOf(this) + 1] || null;
  }
  *descendants() {
    for (const c of this.children) {
      yield c;
      yield* c.descendants();
    }
  }
  contains(other) {
    for (let n = other; n; n = n.parentNode) if (n === this) return true;
    return false;
  }
  querySelectorAll(sel) {
    const parts = sel.trim().split(/\s+/).map(parseCompound);
    const last = parts[parts.length - 1];
    const found = [];
    for (const el of this.descendants()) {
      if (!matches(el, last)) continue;
      // Each earlier part must match some ancestor, in order.
      let i = parts.length - 2;
      for (let n = el.parentNode; n && n !== this.parentNode && i >= 0; n = n.parentNode) {
        if (matches(n, parts[i])) i -= 1;
      }
      if (i < 0) found.push(el);
    }
    return found;
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }
  dispatch(type, extra = {}) {
    const event = { type, target: this, defaultPrevented: false, ...extra };
    event.preventDefault = () => {
      event.defaultPrevented = true;
    };
    for (const fn of this.listeners[type] || []) fn(event);
    return event;
  }
  click() {
    return this.dispatch("click");
  }
  focus() {
    this.ownerDocument.activeElement = this;
  }
}

// A fake clock. Timers only run when the test moves time on, so a test can
// also model a background tab, where the clock moves but timers don't fire.
class Clock {
  constructor() {
    this.now = 1_000_000;
    this.timers = new Map();
    this.next = 1;
  }
  add(fn, ms, repeat) {
    const id = this.next++;
    this.timers.set(id, { fn, at: this.now + Math.max(0, ms || 0), every: repeat ? ms : 0 });
    return id;
  }
  clear(id) {
    this.timers.delete(id);
  }
  // Move the clock on by `ms`, running timers that fall due, in order.
  advance(ms) {
    const end = this.now + ms;
    for (;;) {
      let first = null;
      for (const [id, t] of this.timers) if (t.at <= end && (!first || t.at < first[1].at)) first = [id, t];
      if (!first) break;
      const [id, t] = first;
      this.now = t.at;
      if (t.every) t.at += t.every;
      else this.timers.delete(id);
      t.fn();
    }
    this.now = end;
  }
  // Move the clock without running timers: a throttled background tab.
  skip(ms) {
    this.now += ms;
    for (const t of this.timers.values()) if (t.at < this.now) t.at = this.now;
  }
}

export class Clipboard {
  constructor({ canRead = true } = {}) {
    this.text = "";
    this.writes = [];
    this.refuseWrites = false;
    this.refuseReads = false;
    if (canRead) {
      this.readText = () =>
        this.refuseReads ? Promise.reject(new Error("denied")) : Promise.resolve(this.text);
    }
  }
  writeText(t) {
    if (this.refuseWrites) return Promise.reject(new Error("not focused"));
    this.writes.push(t);
    this.text = t;
    return Promise.resolve();
  }
}

// Build a page. `build(h)` returns the children of <main>; `h(tag, attrs,
// children)` makes an element. Then run app.js against it.
export function page(build, { clipboard = new Clipboard(), body = {}, opener = null, fetch } = {}) {
  const clock = new Clock();
  const doc = {
    activeElement: null,
    visibilityState: "visible",
    listeners: {},
  };
  const h = (tag, attrs, children) => new Element(doc, tag, attrs, children);
  const main = h("main", { id: "main" }, build(h));
  const bodyEl = h("body", body, [main]);
  Object.assign(doc, {
    body: bodyEl,
    createElement: (tag) => h(tag),
    getElementById: (id) => bodyEl.querySelectorAll("*").find((e) => e.id === id) || null,
    querySelector: (s) => bodyEl.querySelector(s),
    querySelectorAll: (s) => bodyEl.querySelectorAll(s),
    addEventListener: Element.prototype.addEventListener,
    dispatch: Element.prototype.dispatch,
  });
  // `*` matches any element in the stub.
  const qsa = Element.prototype.querySelectorAll;
  bodyEl.querySelectorAll = function (s) {
    return s === "*" ? [...this.descendants()] : qsa.call(this, s);
  };
  const assigned = [];
  const fetches = [];
  const win = {
    listeners: {},
    opener,
    closed: false,
    location: { origin: "https://keyring.example", assign: (u) => assigned.push(u) },
    close() {
      this.closed = true;
    },
    addEventListener: Element.prototype.addEventListener,
    dispatch: Element.prototype.dispatch,
  };
  if (fetch !== null) {
    win.fetch = (url, opts) => {
      fetches.push({ url, opts });
      return (fetch || (() => Promise.resolve({ status: 204, redirected: false })))(url, opts);
    };
  }
  const ctx = vm.createContext({
    document: doc,
    window: win,
    navigator: { clipboard },
    Date: { now: () => clock.now },
    setTimeout: (fn, ms) => clock.add(fn, ms, false),
    clearTimeout: (id) => clock.clear(id),
    setInterval: (fn, ms) => clock.add(fn, ms, true),
    clearInterval: (id) => clock.clear(id),
  });
  vm.runInContext(SCRIPT, ctx, { filename: "static/app.js" });
  return { doc, win, main, body: bodyEl, clock, clipboard, assigned, fetches, h };
}

// Let promise callbacks run.
export async function settle() {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
}
