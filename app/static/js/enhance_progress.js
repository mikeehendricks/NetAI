/* "Enhance with AI" progress bar.
 * The enhancement runs as a background job (local models take 1-3+ min), so the
 * button starts the job via fetch, then polls its status and drives a real
 * progress bar: model-load creep while the model warms up, then actual streamed
 * word count vs the ~600-word target. Without JS the classic synchronous form
 * submit still works (progressive enhancement).
 */
(function () {
  "use strict";
  var form = document.getElementById("enhance-form");
  if (!form || !window.fetch) return;
  var panel = document.getElementById("enhance-progress");
  var bar = document.getElementById("enhance-bar");
  var pctEl = document.getElementById("enhance-pct");
  var stageEl = document.getElementById("enhance-stage");
  var metaEl = document.getElementById("enhance-meta");
  var errEl = document.getElementById("enhance-error");
  var startUrl = form.getAttribute("data-start-url");
  var pollBase = form.getAttribute("data-status-url");
  var btn = form.querySelector("button");
  var origLabel = btn ? btn.textContent : "";
  var pollTimer = null, tickTimer = null, t0 = 0, misses = 0;

  function fmt(sec) {
    var m = Math.floor(sec / 60), s = sec % 60;
    return m + ":" + String(s).padStart(2, "0");
  }

  function stopTimers() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
  }

  function stageText(st, words) {
    if (st === "queued") return "Queued\u2026";
    if (st === "load") return "Loading the model into memory (cold start \u2248 15\u201330 s)\u2026";
    if (st === "gen") return "Generating summary" + (words ? " \u2014 " + words + " words" : "") + "\u2026";
    if (st === "done") return "Done \u2014 loading result\u2026";
    return "Failed";
  }

  function showError(msg) {
    stopTimers();
    panel.style.display = "";
    errEl.style.display = "";
    errEl.textContent = msg;
    if (btn) { btn.disabled = false; btn.textContent = origLabel; }
  }

  function poll(jid) {
    fetch(pollBase + jid, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("status " + r.status); return r.json(); })
      .then(function (d) {
        misses = 0;
        bar.style.width = Math.max(2, Math.min(100, d.progress)) + "%";
        pctEl.textContent = Math.round(d.progress) + "%";
        stageEl.textContent = stageText(d.stage, d.words);
        if (d.stage === "done") {
          stopTimers();
          setTimeout(function () { window.location.reload(); }, 600);
        } else if (d.stage === "error") {
          showError(d.error || "Enhancement failed.");
        }
      })
      .catch(function (e) {
        // transient network blips must not kill a 3-minute run; abort after ~20 s of misses
        misses += 1;
        if (misses >= 10) {
          showError("Lost contact with the server (" + e.message + "). The job may still be running \u2014 reload this page in a minute.");
        }
      });
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (btn) { btn.disabled = true; btn.textContent = "Starting\u2026"; }
    errEl.style.display = "none";
    var body = new URLSearchParams(new FormData(form));
    fetch(startUrl, { method: "POST", headers: { "Accept": "application/json" }, body: body })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok || !res.j.ok) throw new Error(res.j && res.j.error || "could not start");
        panel.style.display = "";
        form.style.display = "none";
        t0 = Date.now();
        tickTimer = setInterval(function () {
          metaEl.textContent = "elapsed " + fmt(Math.floor((Date.now() - t0) / 1000)) +
            " \u00b7 local models: 1\u20133 min is normal, the page updates itself when finished";
        }, 1000);
        poll(res.j.jid);
        pollTimer = setInterval(function () { poll(res.j.jid); }, 2000);
      })
      .catch(function (e) {
        if (btn) { btn.disabled = false; btn.textContent = origLabel; }
        showError("Could not start the background job (" + e.message + "). You can retry, or reload the page.");
      });
  });
})();
