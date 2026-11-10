// Keyring browser extras. Hand-written, no dependencies.
// Every page works without this file; it only adds small conveniences.
// tests/js/app.test.mjs runs it in Node against stub DOM objects.
"use strict";

(function () {
  // Set a live region's text so it is announced even when the words are the
  // same as last time: empty it, then fill it a moment later.
  function say(region, text) {
    if (!region) {
      return;
    }
    clearTimeout(region.keyringSay);
    region.textContent = "";
    region.keyringSay = setTimeout(function () {
      region.textContent = text;
    }, 100);
  }

  // Filter table rows as you type. The form still works without JS: it
  // submits and the server filters. Only rows on this page are filtered.
  function liveFilter(form) {
    var table = document.getElementById(form.getAttribute("data-live-filter"));
    var input = form.querySelector('input[type="search"]');
    if (!table || !input) {
      return;
    }
    var wrap = table.parentNode;
    var empty = wrap.nextElementSibling;
    if (empty && !empty.hasAttribute("data-live-filter-empty")) {
      empty = null;
    }
    // The empty message stays blank until it is needed, so it is spoken
    // once when the count reaches zero.
    var emptyText = "";
    if (empty) {
      emptyText = empty.textContent;
      empty.textContent = "";
    }
    var paged = !!(wrap.parentNode && wrap.parentNode.querySelector(".pager"));
    var caption = table.querySelector("caption");
    var plural = caption ? caption.textContent.trim().split(/\s+/)[0].toLowerCase() : "rows";
    var rows = table.querySelectorAll("tbody tr[data-filter-text]");
    var noun = rows.length === 1 ? plural.replace(/s$/, "") : plural;
    // One quiet status line, spoken once typing pauses, not on every key.
    var count = document.createElement("p");
    count.className = "visually-hidden";
    count.setAttribute("role", "status");
    wrap.insertBefore(count, table);
    var pause = null;
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
        if (shown !== 0) {
          empty.textContent = "";
        }
      }
      clearTimeout(pause);
      pause = setTimeout(function () {
        // At zero only the visible message speaks.
        count.textContent = q && shown !== 0
          ? shown + " of " + rows.length + " " + noun + " on this page " +
            (shown === 1 ? "matches." : "match.") +
            (paged ? " Press Filter to search every page." : "")
          : "";
        if (empty && shown === 0) {
          empty.textContent = emptyText;
        }
      }, 300);
    });
  }

  // A revealed secret: copy to clipboard, then after a delay clear the
  // clipboard (only if it still holds our value) and hide the value.
  function reveal(panel) {
    var field = panel.querySelector("[data-secret-value]");
    var copy = panel.querySelector("[data-copy]");
    var extend = panel.querySelector("[data-extend]");
    var use = panel.querySelector("[data-use-value]");
    var status = panel.querySelector("[data-copy-status]");
    var countdown = panel.querySelector("[data-countdown]");
    var secs = panel.querySelector("[data-countdown-secs]");
    var announce = panel.querySelector("[data-countdown-announce]");
    var hideLink = panel.querySelector("[data-hide-link]");
    var delay = parseInt(panel.getAttribute("data-clear-after"), 10) || 30;
    var value = field.value;
    var deadline = 0;
    var warned = false;
    var copied = false; // We wrote the value and haven't cleared it yet.
    var clearing = null;
    var gone = false;

    // Count from a fixed deadline, because background tabs slow timers.
    function restart() {
      deadline = Date.now() + delay * 1000;
      warned = delay <= 20;
      secs.textContent = String(delay);
    }

    // Overwrite the clipboard if it still holds our value. If it can't be
    // read, overwrite anyway: we wrote it moments ago. Browsers refuse this
    // in a background tab, so a failure is tried again when the page is back.
    function clearClipboard(message) {
      if (clearing) {
        return clearing;
      }
      var clip = navigator.clipboard;
      var ours = clip.readText
        ? clip.readText().then(function (now) {
            return now === value;
          }, function () {
            return true;
          })
        : Promise.resolve(true);
      clearing = ours.then(function (mine) {
        if (!mine) {
          copied = false;
          say(status, message);
          return;
        }
        return navigator.clipboard.writeText("").then(function () {
          copied = false;
          say(status, message + " Clipboard cleared.");
        });
      }).then(null, function () {
        say(status, message + " Keyring couldn't clear the clipboard yet. " +
          "It will try again when you come back to this page, or clear it yourself.");
      }).then(function () {
        clearing = null;
      });
      return clearing;
    }

    function hide(message) {
      message = message || "Value hidden.";
      if (!gone) {
        gone = true;
        clearInterval(timer);
        // Don't strand keyboard focus on a button that's about to vanish.
        var hadFocus = panel.contains(document.activeElement);
        field.value = "";
        field.textContent = "";
        field.defaultValue = "";
        [field, copy, extend, use, countdown].forEach(function (el) {
          if (el) {
            el.hidden = true;
          }
        });
        if (hadFocus && hideLink) {
          hideLink.focus();
        }
      }
      if (!copied) {
        say(status, message);
        return Promise.resolve();
      }
      return clearClipboard(message);
    }

    function tick() {
      var left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      secs.textContent = String(left);
      if (left <= 20 && !warned) {
        warned = true;
        say(announce, "Hiding in " + left + " seconds. Choose Show for longer to keep it.");
      }
      if (left <= 0) {
        hide();
      }
    }

    restart();
    countdown.hidden = false;
    say(announce, "Shown for " + delay + " seconds, then hidden." +
      (extend ? " Choose Show for longer to keep it." : ""));
    var timer = setInterval(tick, 1000);

    // Anyone can ask for more time, as often as they need.
    if (extend) {
      extend.hidden = false;
      extend.addEventListener("click", function () {
        restart();
        say(announce, "Shown for another " + delay + " seconds.");
      });
    }

    if (copy && navigator.clipboard && navigator.clipboard.writeText) {
      copy.hidden = false;
      copy.addEventListener("click", function () {
        navigator.clipboard.writeText(value).then(function () {
          copied = true;
          restart();
          say(status, "Copied. Keyring will try to clear the clipboard in " + delay + " seconds.");
        }, function () {
          say(status, "Couldn't copy. Select the value and copy it yourself.");
        });
      });
    }

    // From the generator, opened by a secret form: hand the value back.
    var sameOrigin = false;
    try {
      sameOrigin = !!window.opener && window.opener.location.origin === window.location.origin;
    } catch (e) {
      sameOrigin = false;
    }
    if (use && sameOrigin) {
      use.hidden = false;
      use.addEventListener("click", function () {
        var target = null;
        try {
          target = !window.opener.closed && window.opener.document.getElementById("value");
        } catch (e) {
          target = null;
        }
        if (!target) {
          say(status, "The secret form isn't open any more. Copy the value instead.");
          return;
        }
        target.value = value;
        hide("Added to the secret form.").then(function () {
          window.close();
        });
      });
    }

    // Hide clears the clipboard while this page still has focus, then leaves.
    if (hideLink) {
      hideLink.addEventListener("click", function (event) {
        if (copied) {
          // Leave once the clear is done, or after a second and a half if
          // the browser is waiting on a paste prompt.
          event.preventDefault();
          var left = false;
          var go = function () {
            if (!left) {
              left = true;
              window.location.assign(hideLink.href);
            }
          };
          hide().then(go);
          setTimeout(go, 1500);
        } else {
          hide();
        }
      });
    }

    // Back on the page: catch up on an overdue hide, or retry a failed clear.
    function back() {
      if (!gone) {
        tick();
      } else if (copied) {
        clearClipboard("Value hidden.");
      }
    }
    window.addEventListener("focus", back);
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") {
        back();
      }
    });
    window.addEventListener("pagehide", function () {
      hide();
    });
  }

  // Copy something that isn't secret, such as a public key. No clearing.
  function copyPlain(button) {
    var field = document.getElementById(button.getAttribute("data-copy-plain"));
    var status = document.querySelector("[data-copy-plain-status]");
    if (!field || !navigator.clipboard || !navigator.clipboard.writeText) {
      return;
    }
    var what = button.textContent.replace(/^\s*Copy\s*/, "").trim() || "value";
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(field.value).then(function () {
        say(status, "Copied the " + what + ".");
      }, function () {
        say(status, "Couldn't copy the " + what + ". Select it and copy it yourself.");
      });
    });
  }

  // Warn a few minutes before the idle sign-out, and offer more time.
  // Does nothing unless the page says how long the limit is.
  function idleNotice(body) {
    var limit = parseInt(body.getAttribute("data-idle-seconds"), 10);
    if (!(limit > 0) || !window.fetch) {
      return;
    }
    var lead = Math.min(300, Math.floor(limit / 5));
    var deadline = 0;
    var state = "";
    var region = document.createElement("div");
    region.className = "idle-status";
    region.setAttribute("role", "status");
    var box = document.createElement("div");
    box.className = "notice notice-warn idle-notice";
    var text = document.createElement("p");
    var stay = document.createElement("button");
    stay.type = "button";
    stay.textContent = "Stay signed in";
    box.appendChild(text);
    box.appendChild(stay);
    region.appendChild(box);
    // Where focus goes once the notice closes, so it isn't lost. Outside the
    // live region, so it is read once.
    var done = document.createElement("p");
    done.className = "visually-hidden";
    done.setAttribute("tabindex", "-1");
    var main = document.getElementById("main") || body;
    main.insertBefore(done, main.firstChild);
    main.insertBefore(region, done);

    function reset() {
      deadline = Date.now() + limit * 1000;
      state = "";
      box.hidden = true;
      clearTimeout(text.keyringSay);
      text.textContent = "";
      done.textContent = "";
    }

    function signedOut() {
      state = "out";
      stay.hidden = true;
      box.hidden = false;
      say(text, "You have been signed out because nothing happened for a while. " +
        "Reload the page to sign in again.");
    }

    function check() {
      var left = deadline - Date.now();
      if (left <= 0 && state !== "out") {
        signedOut();
      } else if (left > 0 && left <= lead * 1000 && state === "") {
        state = "warned";
        stay.hidden = false;
        box.hidden = false;
        var mins = Math.max(1, Math.round(left / 60000));
        say(text, "You will be signed out in about " + mins +
          (mins === 1 ? " minute" : " minutes") +
          " because nothing has happened. Choose Stay signed in to keep working.");
      }
    }

    function failed() {
      say(text, "Couldn't reach Keyring. Choose Stay signed in to try again.");
    }

    stay.addEventListener("click", function () {
      window.fetch("/auth/keepalive", { credentials: "same-origin", cache: "no-store" })
        .then(function (res) {
          // An ended session is redirected to the sign-in page instead.
          if (res.status === 204) {
            reset();
            done.textContent = "You're still signed in.";
            done.focus();
          } else if (res.redirected || res.status === 401) {
            signedOut();
          } else {
            failed();
          }
        }, failed);
    });

    reset();
    setInterval(check, 15000);
    document.addEventListener("visibilitychange", check);
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
  idleNotice(document.body);
})();
