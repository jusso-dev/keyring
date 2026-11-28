// Keyring tag rows. Hand-written, no dependencies. Optional: the forms post
// the same fields without it, and the <datalist> suggestions work without it.
// It swaps a row's value list when its name changes, and adds and removes
// rows. Text is set as text, never markup. tests/js/tags.test.mjs runs it.
"use strict";

(function () {
  var ANY = "tag-values-any";

  // The value list for a tag name: that name's own list, or the most used
  // values overall. Names are compared as text, never put in a selector.
  function listFor(name) {
    var lists = document.querySelectorAll("datalist[data-tag-for]");
    for (var i = 0; i < lists.length; i++) {
      if (lists[i].getAttribute("data-tag-for") === name) return lists[i].id;
    }
    return ANY;
  }

  function watch(row) {
    var name = row.querySelector("input[data-tag-name]");
    var value = row.querySelector("input[data-tag-value]");
    if (!name || !value) return;
    var swap = function () {
      value.setAttribute("list", listFor(name.value));
    };
    name.addEventListener("input", swap);
    name.addEventListener("change", swap);
  }

  function el(tag, text) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    return n;
  }

  function field(n, part, max, list) {
    var id = "tag-" + part + "-" + n;
    var box = el("div");
    var label = el("label", "Tag " + n + " " + part);
    label.setAttribute("for", id);
    var input = el("input");
    input.type = "text";
    input.setAttribute("id", id);
    input.setAttribute("name", id);
    input.setAttribute("maxlength", String(max));
    input.setAttribute("list", list);
    input.setAttribute("data-tag-" + part, "");
    input.setAttribute("autocomplete", "off");
    input.setAttribute("autocapitalize", "off");
    input.setAttribute("autocorrect", "off");
    input.setAttribute("spellcheck", "false");
    box.appendChild(label);
    box.appendChild(input);
    return box;
  }

  function number(row) {
    var input = row.querySelector("input[data-tag-name]");
    var m = input ? /^tag-name-(\d+)$/.exec(input.getAttribute("id") || "") : null;
    return m ? parseInt(m[1], 10) : 0;
  }

  function rowsOf(box) {
    return box.querySelectorAll("div[data-tag-row]");
  }

  // A Remove button on a row. Removing a row leaves its tag out of the
  // post, so saving removes the tag. Focus moves to a neighbour's Remove
  // (static/behaviors.js), or to the Add button.
  function removable(row, add) {
    var n = number(row);
    var button = el("button");
    button.type = "button";
    button.className = "button-small button-secondary tag-remove";
    button.appendChild(el("span", "Remove"));
    var hidden = el("span", " tag " + n);
    hidden.className = "visually-hidden";
    button.appendChild(hidden);
    button.addEventListener("click", function () {
      var gone = function () {
        row.parentNode.removeChild(row);
        add.hidden = false;
      };
      var B = window.KeyringBehaviors;
      if (!B) {
        gone();
        add.focus();
        return;
      }
      // Focus goes to the next row's Remove, else the one before, else Add.
      var next = row.nextElementSibling, prev = row.previousElementSibling;
      var pick = function (r) { return r && r.hasAttribute("data-tag-row") ? r.querySelector("button") : null; };
      B.recover(row, gone, [pick(next), pick(prev), add]);
    });
    row.appendChild(button);
  }

  function start(box) {
    var max = parseInt(box.getAttribute("data-tag-max") || "0", 10);
    var add = el("button", "Add a tag");
    add.type = "button";
    add.className = "button-small button-secondary tag-add";
    var anchor = rowsOf(box);
    anchor.forEach(function (row) {
      watch(row);
      removable(row, add);
    });
    add.addEventListener("click", function () {
      // The lowest free number, so a row removed at the limit can be
      // added back.
      var used = {};
      var count = 0;
      rowsOf(box).forEach(function (r) {
        used[number(r)] = true;
        count++;
      });
      var n = 1;
      while (used[n]) n++;
      if (n > max) {
        add.hidden = true;
        return;
      }
      var row = el("div");
      row.className = "tag-row";
      row.setAttribute("data-tag-row", "");
      row.appendChild(field(n, "name", 512, "tag-names"));
      row.appendChild(field(n, "value", 256, ANY));
      box.insertBefore(row, add);
      watch(row);
      removable(row, add);
      add.hidden = count + 1 >= max;
      row.querySelector("input[data-tag-name]").focus();
    });
    box.appendChild(add);
    add.hidden = anchor.length > 0 && number(anchor[anchor.length - 1]) >= max;
  }

  try {
    document.querySelectorAll("fieldset[data-tag-rows]").forEach(start);
    // The bulk change's single tag name and value.
    document.querySelectorAll("form[data-tag-row]").forEach(watch);
  } catch (e) {
    // A browser extra only: the form already works without it.
  }
})();
