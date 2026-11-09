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

  // A revealed secret: copy to clipboard, then after a delay clear the
  // clipboard (only if it still holds our value) and hide the value.
  function reveal(panel) {
    var field = panel.querySelector("[data-secret-value]");
    var copy = panel.querySelector("[data-copy]");
    var status = panel.querySelector("[data-copy-status]");
    var countdown = panel.querySelector("[data-countdown]");
    var secs = panel.querySelector("[data-countdown-secs]");
    var hideLink = panel.querySelector("[data-hide-link]");
    var delay = parseInt(panel.getAttribute("data-clear-after"), 10) || 30;
    var left = delay;
    var copied = false;
    var timer = null;

    function hide() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      var value = field.value;
      field.value = "";
      field.hidden = true;
      if (copy) {
        copy.hidden = true;
      }
      countdown.hidden = true;
      if (copied && navigator.clipboard && navigator.clipboard.readText) {
        // Reading needs permission. If we can't read, still overwrite: we
        // only ever wrote this value, moments ago.
        navigator.clipboard.readText().then(function (current) {
          if (current === value) {
            return navigator.clipboard.writeText("");
          }
        }, function () {
          return navigator.clipboard.writeText("");
        }).then(function () {
          status.textContent = "Value hidden and clipboard cleared.";
        }, function () {
          status.textContent = "Value hidden. Clear your clipboard yourself.";
        });
      } else {
        status.textContent = "Value hidden.";
      }
      value = null;
      copied = false;
    }

    function tick() {
      left -= 1;
      secs.textContent = String(left);
      if (left <= 0) {
        hide();
      }
    }

    countdown.hidden = false;
    timer = setInterval(tick, 1000);

    if (copy && navigator.clipboard && navigator.clipboard.writeText) {
      copy.hidden = false;
      copy.addEventListener("click", function () {
        navigator.clipboard.writeText(field.value).then(function () {
          copied = true;
          left = delay;
          secs.textContent = String(left);
          status.textContent = "Copied. The clipboard clears in " + delay + " seconds.";
        }, function () {
          status.textContent = "Couldn't copy. Select the value and copy it yourself.";
        });
      });
    }

    if (hideLink) {
      hideLink.addEventListener("click", function () {
        hide();
      });
    }

    // Leaving the page or switching tabs away for good: wipe it.
    window.addEventListener("pagehide", hide);
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "hidden" && !copied) {
        hide();
      }
    });
  }

  document.querySelectorAll("form[data-live-filter]").forEach(liveFilter);
  document.querySelectorAll("[data-reveal]").forEach(reveal);
})();
