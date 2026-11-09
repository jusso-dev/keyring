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

    // Screen readers hear the countdown at the start and with 10 seconds
    // left, not every second.
    var announce = panel.querySelector("[data-countdown-announce]");
    function say(text) {
      if (announce) {
        announce.textContent = text;
      }
    }

    function tick() {
      left -= 1;
      secs.textContent = String(left);
      if (left === 10) {
        say("Hiding in 10 seconds.");
      }
      if (left <= 0) {
        hide();
      }
    }

    countdown.hidden = false;
    say("Shown for " + delay + " seconds, then hidden.");
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

    // From the generator, opened by a secret form: hand the value back.
    var use = panel.querySelector("[data-use-value]");
    var sameOriginOpener = false;
    try {
      sameOriginOpener = !!window.opener && window.opener.location.origin === window.location.origin;
    } catch (e) {
      sameOriginOpener = false;
    }
    if (use && sameOriginOpener) {
      use.hidden = false;
      use.addEventListener("click", function () {
        var target = window.opener.document.getElementById("value");
        if (target) {
          target.value = field.value;
          status.textContent = "Added to the secret form.";
          hide();
          window.close();
        }
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

  // Copy something that isn't secret, such as a public key. No clearing.
  function copyPlain(button) {
    var field = document.getElementById(button.getAttribute("data-copy-plain"));
    var status = document.querySelector("[data-copy-plain-status]");
    if (!field || !navigator.clipboard || !navigator.clipboard.writeText) {
      return;
    }
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(field.value).then(function () {
        if (status) {
          status.textContent = "Copied.";
        }
      });
    });
  }

  // After a failed form, move focus to the list of problems so keyboard
  // and screen reader users start there.
  var summary = document.querySelector("[data-error-summary]");
  if (summary) {
    summary.focus();
  }

  document.querySelectorAll("form[data-live-filter]").forEach(liveFilter);
  document.querySelectorAll("[data-copy-plain]").forEach(copyPlain);
  document.querySelectorAll("[data-reveal]").forEach(reveal);
})();
