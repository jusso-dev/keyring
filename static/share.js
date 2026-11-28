// Keyring share picker (#286). Hand-written, no dependencies. On the Share
// form only: as you type a name it asks Keyring's own same-origin endpoint
// (which asks Microsoft Graph as you) and lists people and security groups.
// Results are written with textContent only. Without it the form still
// takes an exact email address or object ID. With static/behaviors.js the
// box is a combobox: arrow keys move through the results, Enter picks one.
// tests/js/share.test.mjs runs it in Node against stub DOM objects.
"use strict";

(function () {
  var MIN = 2;
  var MAX = 64;
  var WAIT_MS = 300;
  // The endpoint is a local path under one vault, as the server renders it.
  var URL_RE = /^\/v\/[A-Za-z0-9-]+\/share\/people$/;
  var GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  var TYPES = { Person: 1, Guest: 1, Group: 1 };

  function text(v, max) {
    return typeof v === "string" ? v.slice(0, max) : "";
  }

  // Anything but the five fields the server sends, in their shapes, is dropped.
  function row(r) {
    if (!r || typeof r !== "object" || typeof r.id !== "string" || !GUID_RE.test(r.id)) {
      return null;
    }
    if (!TYPES.hasOwnProperty(r.type)) {
      return null;
    }
    return { id: r.id, name: text(r.name, 120), mail: text(r.mail, 254), upn: text(r.upn, 254), type: r.type };
  }

  function start() {
    var form = document.querySelector("form[data-share-picker]");
    if (!form) {
      return;
    }
    var url = form.getAttribute("data-share-picker");
    var input = form.querySelector("input[data-share-query]");
    var hidden = form.querySelector("input[data-share-principal]");
    var list = form.querySelector("ul[data-share-results]");
    var status = form.querySelector("p[data-share-status]");
    if (!URL_RE.test(url || "") || !input || !hidden || !list || !status || !window.fetch) {
      return;
    }
    var timer = null;
    var asked = 0;
    var B = window.KeyringBehaviors;
    var combo = B ? B.combobox(input, list, { choose: function (b) { b.click(); }, clear: function () { hidden.value = ""; clear(); status.textContent = ""; } }) : null;

    function clear() {
      while (list.firstChild) {
        list.removeChild(list.firstChild);
      }
      list.hidden = true;
      if (combo) combo.close();
    }

    function choose(r) {
      // A search still waiting, or still on its way, would reopen the list.
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      asked++;
      hidden.value = r.id;
      input.value = r.name || r.mail || r.upn || r.id;
      clear();
      status.textContent = "Picked " + (r.name || r.id) + " (" + r.type + ").";
      input.focus();
    }

    function show(results) {
      clear();
      results.forEach(function (r, i) {
        var li = document.createElement("li");
        var b = document.createElement("button");
        b.type = "button";
        if (combo) {
          // An option of the listbox: the input keeps focus, so no tab stop.
          li.setAttribute("role", "presentation");
          b.setAttribute("role", "option");
          b.setAttribute("id", "share-option-" + i);
          b.setAttribute("tabindex", "-1");
        }
        b.className = "button-link";
        b.textContent = (r.name || r.id) + " (" + r.type + ")";
        var detail = document.createElement("span");
        detail.className = "muted small";
        detail.textContent = " " + (r.mail || r.upn);
        b.appendChild(detail);
        b.addEventListener("click", function () {
          choose(r);
        });
        li.appendChild(b);
        list.appendChild(li);
      });
      list.hidden = results.length === 0;
      if (combo) combo.refresh();
    }

    function search(q) {
      var mine = ++asked;
      window
        .fetch(url + "?q=" + encodeURIComponent(q), {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          redirect: "error",
        })
        .then(function (res) {
          return res.json();
        })
        .then(function (body) {
          if (mine !== asked) {
            return;
          }
          var results = Array.isArray(body && body.results) ? body.results.map(row).filter(Boolean) : [];
          show(results);
          var msg = body && typeof body.message === "string" ? text(body.message, 300) : "";
          status.textContent = msg || (results.length ? results.length + " found. Pick one." : "Nobody found. Type their email address or object ID instead.");
        })
        .catch(function () {
          if (mine === asked) {
            clear();
            status.textContent = "Search isn't working just now. Type their email address or object ID instead.";
          }
        });
    }

    input.addEventListener("input", function () {
      // Typing again drops the earlier pick, so a stale ID is never sent.
      hidden.value = "";
      if (timer) {
        clearTimeout(timer);
      }
      var q = input.value.trim().slice(0, MAX);
      if (q.length < MIN || GUID_RE.test(q.toLowerCase()) || q.indexOf("@") > 0) {
        asked++;
        clear();
        status.textContent = "";
        return;
      }
      timer = setTimeout(function () {
        search(q);
      }, WAIT_MS);
    });
  }

  try {
    start();
  } catch (e) {
    // The form works without the picker.
  }
})();
