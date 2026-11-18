// Keyring interaction behaviours. Hand-written, no dependencies, same origin.
// Behaviour after Vercel UI SDK, Apache-2.0 (github.com/vercel-labs/ui, read
// at f01793c82e85): its menu typeahead, combobox keyboard model and focus
// recovery, written again here for plain markup. None of its code is copied.
// Each behaviour enhances markup that already works without script, and
// attaches by a data attribute. Text is never written as markup.
// static/share.js and static/tags.js use it through window.KeyringBehaviors.
// tests/js/behaviors.test.mjs runs it in Node against stub DOM objects.
"use strict";

(function () {
  // Letters typed closer together than this build one search.
  var TYPE_MS = 500;

  function list(nodes) {
    return Array.prototype.slice.call(nodes);
  }

  function shown(el) {
    for (var n = el; n && n !== document.body; n = n.parentNode) {
      if (n.hidden) return false;
    }
    return true;
  }

  function attached(el) {
    return !!el && document.body.contains(el);
  }

  function usable(el) {
    return !!el && !el.disabled && !el.hasAttribute("disabled") && attached(el) && shown(el);
  }

  function within(root, el) {
    return !!el && root.contains(el);
  }

  // Focus recovery. `change` may remove or hide the element that holds
  // focus. If focus was inside `scope` before and is lost after (on the
  // body, or on an element that is gone or hidden), it moves to the first
  // usable element in `fallbacks`, so a keyboard user keeps their place.
  // Something else that took focus meanwhile keeps it.
  function recover(scope, change, fallbacks) {
    var had = within(scope, document.activeElement);
    change();
    var now = document.activeElement;
    if (!had || (now && now !== document.body && attached(now) && shown(now))) {
      return null;
    }
    for (var i = 0; i < fallbacks.length; i++) {
      if (usable(fallbacks[i])) {
        fallbacks[i].focus();
        return fallbacks[i];
      }
    }
    return null;
  }

  // Typeahead. Letters typed within TYPE_MS make a prefix, and the match is
  // the next item whose text starts with it, after the current one. The
  // same letter typed again steps through the items that start with it.
  function typeahead() {
    var typed = "";
    var at = -Infinity;
    return function (key, items, current) {
      var now = Date.now();
      typed = now - at > TYPE_MS ? key.toLowerCase() : typed + key.toLowerCase();
      at = now;
      var q = /^(.)\1*$/.test(typed) ? typed.charAt(0) : typed;
      var start = items.indexOf(current);
      // A longer prefix may still match the current item, so it is tried first.
      for (var i = q.length > 1 ? 0 : 1; i <= items.length; i++) {
        var item = items[(start + i + items.length) % items.length];
        if (item.textContent.trim().toLowerCase().indexOf(q) === 0) return item;
      }
      return null;
    };
  }

  function plainKey(e) {
    return !e.altKey && !e.ctrlKey && !e.metaKey;
  }

  // A <details> menu (data-behavior="menu"): a disclosure, not role="menu",
  // since its items are links and forms that keep their own semantics. The
  // summary says aria-expanded. Opening it focuses the first item; arrows,
  // Home and End move between items, and letters jump to one. Escape closes
  // it and returns to the summary. A click outside or a Tab away closes it.
  function menu(box) {
    var summary = box.querySelector("summary");
    var body = box.querySelector("ul");
    if (!summary || !body) return;
    var find = typeahead();

    function items() {
      var out = [];
      list(body.querySelectorAll("li")).forEach(function (li) {
        var el = li.querySelector("a") || li.querySelector("button");
        if (usable(el)) out.push(el);
      });
      return out;
    }
    function sync() {
      summary.setAttribute("aria-expanded", box.open ? "true" : "false");
    }
    function close(refocus) {
      box.open = false;
      sync();
      if (refocus) summary.focus();
    }
    function move(to) {
      var all = items();
      if (!all.length) return;
      var i = all.indexOf(document.activeElement);
      var n;
      if (to === "first") n = 0;
      else if (to === "last") n = all.length - 1;
      else if (i < 0) n = to > 0 ? 0 : all.length - 1;
      else n = (i + to + all.length) % all.length;
      all[n].focus();
    }

    box.addEventListener("toggle", function () {
      sync();
      if (box.open && !within(body, document.activeElement)) move("first");
    });
    box.addEventListener("keydown", function (e) {
      if (!plainKey(e)) return;
      if (e.key === "Escape" && box.open) {
        e.preventDefault();
        close(true);
        return;
      }
      if (e.target === summary) {
        if (!box.open && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
          e.preventDefault();
          box.open = true;
          sync();
          move(e.key === "ArrowUp" ? "last" : "first");
        }
        return;
      }
      var step = { ArrowDown: 1, ArrowUp: -1, Home: "first", End: "last" }[e.key];
      if (step !== undefined) {
        e.preventDefault();
        move(step);
      } else if (e.key.length === 1 && e.key !== " ") {
        var hit = find(e.key, items(), document.activeElement);
        if (hit) {
          e.preventDefault();
          hit.focus();
        }
      }
    });
    // Tab away: focus went somewhere outside the menu.
    box.addEventListener("focusout", function (e) {
      if (box.open && e.relatedTarget && !within(box, e.relatedTarget)) close(false);
    });
    document.addEventListener("click", function (e) {
      if (box.open && !within(box, e.target)) close(false);
    });
    sync();
  }

  // A combobox over a list the caller fills. The input keeps focus; Arrow
  // Down and Up open the list and move a highlight through its options,
  // named by aria-activedescendant. Enter picks the highlighted option,
  // Alt+Arrow Up and Tab close the list, and Escape closes it, then clears
  // the text. Options are elements with role="option" and an id.
  // `opts.choose(option)` picks one; `opts.clear()` runs after Escape
  // clears. The caller announces the result count in its own status region.
  function combobox(input, box, opts) {
    var current = null;
    if (!box.getAttribute("id")) box.setAttribute("id", (input.getAttribute("id") || "combo") + "-options");
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-controls", box.getAttribute("id"));
    box.setAttribute("role", "listbox");

    function options() {
      return list(box.querySelectorAll("[role=\"option\"]"));
    }
    function isOpen() {
      return !box.hidden;
    }
    function highlight(el) {
      if (current) current.setAttribute("aria-selected", "false");
      current = el;
      if (el) {
        el.setAttribute("aria-selected", "true");
        input.setAttribute("aria-activedescendant", el.getAttribute("id"));
        if (el.scrollIntoView) el.scrollIntoView({ block: "nearest" });
      } else {
        input.removeAttribute("aria-activedescendant");
      }
    }
    // After the caller changes the options: nothing highlighted, open if any.
    function refresh() {
      highlight(null);
      box.hidden = options().length === 0;
      input.setAttribute("aria-expanded", isOpen() ? "true" : "false");
    }
    function close() {
      highlight(null);
      box.hidden = true;
      input.setAttribute("aria-expanded", "false");
    }
    function step(by) {
      var all = options();
      if (!all.length) return;
      var wasOpen = isOpen();
      box.hidden = false;
      input.setAttribute("aria-expanded", "true");
      var i = wasOpen ? all.indexOf(current) : -1;
      highlight(all[i < 0 ? (by > 0 ? 0 : all.length - 1) : (i + by + all.length) % all.length]);
    }

    input.addEventListener("keydown", function (e) {
      if (e.ctrlKey || e.metaKey) return;
      if (e.altKey) {
        if (e.key === "ArrowDown" && options().length) {
          e.preventDefault();
          box.hidden = false;
          input.setAttribute("aria-expanded", "true");
        } else if (e.key === "ArrowUp" && isOpen()) {
          e.preventDefault();
          close();
        }
        return;
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        step(e.key === "ArrowDown" ? 1 : -1);
      } else if (e.key === "Enter" && isOpen() && current) {
        e.preventDefault();
        opts.choose(current);
      } else if (e.key === "Escape") {
        if (isOpen()) {
          e.preventDefault();
          close();
        } else if (input.value) {
          e.preventDefault();
          input.value = "";
          if (opts.clear) opts.clear();
        }
      } else if (e.key === "Tab") {
        close();
      }
    });
    input.setAttribute("aria-expanded", isOpen() ? "true" : "false");
    return { refresh: refresh, close: close };
  }

  window.KeyringBehaviors = { recover: recover, combobox: combobox, menu: menu };

  try {
    list(document.querySelectorAll("details[data-behavior=\"menu\"]")).forEach(menu);
  } catch (e) {
    // The menus work without it: they are <details> elements.
  }
})();
