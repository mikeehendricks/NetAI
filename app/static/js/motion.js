/* NetAI motion layer — Anime.js-powered micro-animations (progressive enhancement).
 *
 * Purpose of each effect (usability, not decoration):
 *   1. page cards reveal        — guides the eye to content after navigation
 *   2. flash messages           — slide in for attention; success notes auto-dismiss
 *   3. dashboard counters       — count-up draws the eye to the key numbers
 *   4. risk score pill          — pop makes the headline result unmissable
 *   5. dynamic table rows       — new rows (live map, commits, audit) fade in so
 *                                 refreshes are noticed instead of silently swapping
 *   6. busy submit buttons      — pulse while an operation runs (analysis takes
 *                                 seconds) so the click clearly registered
 *
 * Everything here is optional: if Anime.js fails to load, or the user has
 * prefers-reduced-motion set, the site renders instantly and stays fully
 * functional. No inline JS is used (CSP: script-src 'self').
 */
(function () {
  "use strict";
  if (!window.anime) return;                       // library missing: static UI
  var reduced = false;
  try {
    reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch (e) { /* old browser: treat as not reduced */ }
  if (reduced) return;                             // user asked for less motion

  function rows(t) { return Array.prototype.slice.call(t || []); }
  function shown(el) { return !!(el.offsetWidth && el.offsetHeight); }

  // 1) reveal page cards once on load (skip very long pages)
  try {
    var cards = rows(document.querySelectorAll("main .card, main .authcard")).filter(shown);
    if (cards.length && cards.length <= 12) {
      anime({ targets: cards, opacity: [0, 1], translateY: [10, 0],
              duration: 420, easing: "easeOutQuad", delay: anime.stagger(55) });
    }
  } catch (e) { /* never break the page over an animation */ }

  // 2) flash messages: slide in; success notes auto-dismiss after 6s
  try {
    var flashes = rows(document.querySelectorAll(".flashes .alert"));
    if (flashes.length) {
      anime({ targets: flashes, opacity: [0, 1], translateY: [-8, 0],
              duration: 320, easing: "easeOutQuad", delay: anime.stagger(70) });
    }
    rows(document.querySelectorAll(".flashes .alert-success")).forEach(function (el) {
      setTimeout(function () {
        anime({ targets: el, opacity: 0, translateY: -6, duration: 380, easing: "easeInQuad",
                complete: function () { if (el.parentNode) el.parentNode.removeChild(el); } });
      }, 6000);
    });
  } catch (e) { /* ignore */ }

  // 3) dashboard stat counters count up
  try {
    rows(document.querySelectorAll(".statnum")).forEach(function (el) {
      var m = (el.textContent || "").trim().match(/^\d+$/);
      if (!m || parseInt(m[0], 10) === 0) return;
      var o = { v: 0 };
      anime({ targets: o, v: parseInt(m[0], 10), duration: 900, easing: "easeOutCubic",
              round: 1, update: function () { el.textContent = o.v; } });
    });
  } catch (e) { /* ignore */ }

  // 4) risk score pill pop
  try {
    var pill = document.querySelector(".scorepill");
    if (pill) {
      anime({ targets: pill, scale: [0.85, 1], opacity: [0, 1],
              duration: 500, easing: "easeOutBack" });
    }
  } catch (e) { /* ignore */ }

  // 5) dynamically added table rows fade in (live map, commits, users, audit)
  try {
    if (window.MutationObserver) {
      var io = new MutationObserver(function (muts) {
        muts.forEach(function (mu) {
          rows(mu.addedNodes).forEach(function (n) {
            if (n.nodeType === 1 && n.tagName === "TR") {
              anime({ targets: n, opacity: [0, 1], translateX: [-6, 0],
                      duration: 260, easing: "easeOutQuad" });
            }
          });
        });
      });
      rows(document.querySelectorAll(".tbl tbody")).forEach(function (tb) {
        io.observe(tb, { childList: true });
      });
    }
  } catch (e) { /* ignore */ }

  // 6) busy submit buttons pulse while a form is submitting
  var busyAnim = null;
  document.addEventListener("submit", function (e) {
    if (e.defaultPrevented) return;                // a confirm/cancel or validation said no
    var f = e.target;
    if (!f || !f.matches || !f.matches("form")) return;
    var btn = f.querySelector('button[type="submit"], button:not([type])');
    if (!btn) return;
    setTimeout(function () {                       // app.js disables the button in a 0ms timer
      if (!btn.disabled) return;
      busyAnim = anime({ targets: btn, opacity: [1, 0.55], direction: "alternate",
                         loop: true, duration: 700, easing: "easeInOutSine" });
    }, 30);
  });
  // back/forward navigation restores the button (app.js) - stop the pulse too
  window.addEventListener("pageshow", function () {
    if (busyAnim) {
      busyAnim.pause();
      anime.set(busyAnim.animatables.map(function (a) { return a.target; }), { opacity: 1 });
      busyAnim = null;
    }
  });
})();
