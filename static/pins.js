// Keyring pinned and recently opened items. Hand-written, no dependencies.
// Kept in this browser's localStorage under one key: names, kinds and local
// paths only, never values or tokens. Pages work without it or localStorage.
// tests/js/pins.test.mjs runs it in Node against stub DOM objects.
"use strict";

(function () {
  var KEY = "keyring.pins";
  var MAX_PINNED = 50;
  var MAX_RECENT = 10;
  var SECTIONS = { vault: "secrets", secret: "secrets", certificate: "certificates", key: "keys" };
  // The same shapes the server accepts for a vault name and an item name.
  var VAULT_RE = /^[A-Za-z](?!.*--)[A-Za-z0-9-]{1,22}[A-Za-z0-9]$/;
  var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,126}$/;
  // A local path only: no scheme, no "//", no backslash, no control characters.
  var PATH_RE = /^\/v\/[A-Za-z0-9-]+\/(secrets|certificates|keys)(\/[A-Za-z0-9-]+)?$/;

  // localStorage, or null when the browser refuses it (private mode, policy).
  function storage() {
    try {
      var s = window.localStorage;
      s.setItem(KEY + ".probe", "1");
      s.removeItem(KEY + ".probe");
      return s;
    } catch (e) {
      return null;
    }
  }

  function clear() {
    try {
      window.localStorage.removeItem(KEY);
    } catch (e) {
      // Storage refused: nothing was kept.
    }
  }

  function pathFor(kind, vault, name) {
    var path = "/v/" + vault + "/" + SECTIONS[kind];
    return kind === "vault" ? path : path + "/" + name;
  }

  // Anything other than exactly what this script writes is dropped.
  function valid(e) {
    if (!e || typeof e !== "object" || !SECTIONS.hasOwnProperty(e.kind)) {
      return false;
    }
    var names = typeof e.vault === "string" && VAULT_RE.test(e.vault) && typeof e.name === "string" && NAME_RE.test(e.name);
    return names && (e.kind !== "vault" || e.name === e.vault) && typeof e.path === "string" &&
      PATH_RE.test(e.path) && e.path === pathFor(e.kind, e.vault, e.name);
  }

  function tidy(list, max) {
    return Array.isArray(list) ? list.filter(valid).slice(0, max) : [];
  }

  function load(store) {
    var data = null;
    try {
      data = JSON.parse(store.getItem(KEY) || "null");
    } catch (e) {
      // Unreadable: start again.
    }
    data = data && typeof data === "object" ? data : {};
    return { pinned: tidy(data.pinned, MAX_PINNED), recent: tidy(data.recent, MAX_RECENT) };
  }

  // False when the browser refuses the write (quota, private mode).
  function save(store, data) {
    try {
      store.setItem(KEY, JSON.stringify({ pinned: data.pinned, recent: data.recent }));
      return true;
    } catch (e) {
      return false;
    }
  }

  // `list` without `entry`, then `entry` first when `add` is set.
  function put(list, entry, add, max) {
    var rest = list.filter(function (e) {
      return e.path !== entry.path;
    });
    return (add ? [entry].concat(rest) : rest).slice(0, max);
  }

  function pinned(store, entry) {
    return load(store).pinned.some(function (e) {
      return e.path === entry.path;
    });
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    n.className = cls || "";
    n.textContent = text || "";
    return n;
  }

  // The star beside a vault or item heading: a real button with a pressed
  // state. The visible label stays "Pin"; the glyph fills when pinned.
  function star(store, heading, entry) {
    var row = el("p", "pin-row");
    var button = el("button", "button-small button-secondary pin-button");
    button.type = "button";
    button.appendChild(el("span", "", "Pin"));
    button.appendChild(el("span", "visually-hidden", " " + entry.name));
    button.setAttribute("aria-pressed", String(pinned(store, entry)));
    button.addEventListener("click", function () {
      var data = load(store);
      var on = !pinned(store, entry);
      data.pinned = put(data.pinned, entry, on, MAX_PINNED);
      if (save(store, data)) {
        button.setAttribute("aria-pressed", String(on));
      }
    });
    row.appendChild(button);
    heading.parentNode.insertBefore(row, heading.nextElementSibling);
  }

  function section(title, id, list) {
    var box = el("section", "pins");
    box.setAttribute("aria-labelledby", id);
    var h = el("h2", "", title);
    h.setAttribute("id", id);
    var ul = el("ul", "pin-list");
    list.forEach(function (e) {
      var li = el("li");
      var a = el("a", "item-name", e.name);
      a.setAttribute("href", e.path);
      li.appendChild(a);
      li.appendChild(el("span", "muted", e.kind === "vault" ? " vault" : " " + e.kind + " in " + e.vault));
      ul.appendChild(li);
    });
    box.appendChild(h);
    box.appendChild(ul);
    return box;
  }

  // Pinned and Recently opened, shown only when there is something to show.
  function lists(store, mount) {
    var data = load(store);
    if (data.pinned.length) {
      mount.appendChild(section("Pinned", "pins-pinned", data.pinned));
    }
    if (data.recent.length) {
      mount.appendChild(section("Recently opened", "pins-recent", data.recent));
    }
    if (!mount.firstChild) return;
    var note = el("p", "muted", "Kept in this browser only, and cleared when you sign out. ");
    var button = el("button", "button-link", "Clear");
    button.type = "button";
    button.addEventListener("click", function () {
      var gone = function () {
        clear();
        mount.hidden = true;
      };
      // The button that had focus is about to vanish: keep the keyboard
      // user's place on the page's heading.
      var B = window.KeyringBehaviors;
      var heading = document.querySelector("main h1");
      if (heading && !heading.hasAttribute("tabindex")) {
        heading.setAttribute("tabindex", "-1");
      }
      if (B) {
        B.recover(mount, gone, [heading]);
      } else {
        gone();
        if (heading) heading.focus();
      }
    });
    note.appendChild(button);
    mount.appendChild(note);
    mount.hidden = false;
  }

  function start() {
    // Signing out clears the list. A plain listener, so no inline script.
    document.querySelectorAll("form[data-pins-clear]").forEach(function (form) {
      form.addEventListener("submit", clear);
    });
    if (document.querySelector("[data-pins-signed-out]")) {
      clear();
      return;
    }
    var store = storage();
    if (!store) return;
    var heading = document.querySelector("[data-pin]");
    if (heading) {
      var kind = heading.getAttribute("data-pin");
      var vault = heading.getAttribute("data-pin-vault") || "";
      var entry = { kind: kind, vault: vault, name: kind === "vault" ? vault : heading.getAttribute("data-pin-name") || "" };
      entry.path = SECTIONS.hasOwnProperty(kind) ? pathFor(kind, vault, entry.name) : "";
      if (valid(entry)) {
        star(store, heading, entry);
        if (kind !== "vault") {
          var data = load(store);
          data.recent = put(data.recent, entry, true, MAX_RECENT);
          save(store, data);
        }
      }
    }
    var mount = document.querySelector("[data-pins]");
    if (mount) {
      lists(store, mount);
    }
  }

  try {
    start();
  } catch (e) {
    // A browser extra only: the page already works without it.
  }
})();
