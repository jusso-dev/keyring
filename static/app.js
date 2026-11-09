// Keyring browser extras. Hand-written, no dependencies.
// Every page works without this file; it only adds small conveniences.
"use strict";

(function () {
  // Filter table rows as you type. The form still works without JS: it
  // submits and the server filters.
  function liveFilter(form) {
    var table = document.getElementById(form.getAttribute("data-live-filter"));
    var input = form.querySelector('input[type="search"]');
    var empty = document.querySelector("[data-live-filter-empty]");
    if (!table || !input) {
      return;
    }
    var rows = table.querySelectorAll("tbody tr[data-filter-text]");
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (row) {
        var hit = row.getAttribute("data-filter-text").indexOf(q) !== -1;
        row.hidden = !hit;
        if (hit) {
          shown += 1;
        }
      });
      if (empty) {
        empty.hidden = shown !== 0;
      }
    });
  }

  document.querySelectorAll("form[data-live-filter]").forEach(liveFilter);
})();
