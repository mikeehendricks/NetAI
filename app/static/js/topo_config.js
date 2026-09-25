// Config generator: client-side validation + background job with progress bar.
// Local vision models take 2-5 min per diagram, so the image form runs as a
// background job (bg=1) and polls for progress; without JS the classic
// synchronous POST still works. The project form stays synchronous (offline+fast).
(function () {
  "use strict";
  var form = document.getElementById("topoimg-form");
  if (!form) return;
  var inp = document.getElementById("topo_image");
  var err = document.getElementById("topoimg-error");
  var panel = document.getElementById("topo-progress");
  var bar = document.getElementById("topo-bar");
  var pctEl = document.getElementById("topo-pct");
  var stageEl = document.getElementById("topo-stage");
  var metaEl = document.getElementById("topo-meta");
  var errBox = document.getElementById("topo-error");
  var pollBase = form.getAttribute("data-status-url");
  var resultBase = form.getAttribute("data-result-url");
  var btn = form.querySelector("button[type=submit]");
  var pollTimer = null, tickTimer = null, lastPct = 0, lastElapsed = 0, misses = 0;

  function fmt(sec) {
    sec = Math.max(0, Math.round(sec));
    var m = Math.floor(sec / 60), s = sec % 60;
    return m + ":" + String(s).padStart(2, "0");
  }

  function stopTimers() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
  }

  function stageText(st, chars) {
    if (st === "queued") return "Queued\u2026";
    if (st === "load") return "Loading the vision model into memory (cold start \u2248 15\u201330 s)\u2026";
    if (st === "vision") return "Reading the diagram" + (chars ? " \u2014 " + chars + " chars read" : "") + "\u2026";
    if (st === "configs") return "Topology recognized \u2014 generating configurations\u2026";
    if (st === "done") return "Done \u2014 opening result\u2026";
    return "Failed";
  }

  function metaText() {
    var txt = "elapsed " + fmt(lastElapsed) + " \u00b7 local models: 2\u20135 min is normal";
    if (lastPct >= 6 && lastPct < 100) {
      txt += " \u00b7 \u2248 " + fmt(lastElapsed * (100 - lastPct) / lastPct) + " remaining";
    }
    return txt;
  }

  function showError(msg) {
    stopTimers();
    panel.style.display = "";
    errBox.style.display = "";
    errBox.textContent = msg;
    if (btn) { btn.disabled = false; btn.textContent = "Generate from image"; }
  }

  function poll(jid) {
    fetch(pollBase + jid, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("status " + r.status); return r.json(); })
      .then(function (d) {
        misses = 0;
        lastPct = d.progress; lastElapsed = d.elapsed;
        bar.style.width = Math.max(2, Math.min(100, d.progress)) + "%";
        pctEl.textContent = Math.round(d.progress) + "%";
        stageEl.textContent = stageText(d.stage, d.chars);
        metaEl.textContent = metaText();
        if (d.stage === "done" && d.rid) {
          stopTimers();
          window.location.href = resultBase + d.rid;
        } else if (d.stage === "error") {
          showError(d.error || "Generation failed.");
        }
      })
      .catch(function (e) {
        misses += 1;
        if (misses >= 10) {
          showError("Lost contact with the server (" + e.message + "). The job may still be running \u2014 reload this page in a few minutes.");
        }
      });
  }

  form.addEventListener("submit", function (e) {
    if (e.defaultPrevented) return;
    if (!window.fetch) return;             // ancient browser: sync POST fallback
    if (btn && btn.disabled) return;
    var f = inp && inp.files && inp.files[0];
    if (!f) {
      e.preventDefault();
      err.style.display = "";
      err.textContent = "Choose a topology image (PNG or JPEG) first.";
      return;
    }
    if (f.size > 8 * 1024 * 1024) {
      e.preventDefault();
      err.style.display = "";
      err.textContent = "That image is larger than 8 MB. Export it at a lower resolution.";
      return;
    }
    // background flow
    e.preventDefault();
    if (btn) { btn.disabled = true; btn.textContent = "Starting\u2026"; }
    err.style.display = "none";
    errBox.style.display = "none";
    var body = new FormData(form);
    body.append("bg", "1");
    fetch(form.action, { method: "POST", body: body, headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok || !res.j.ok) throw new Error((res.j && res.j.error) || "could not start");
        panel.style.display = "";
        form.style.display = "none";
        poll(res.j.jid);
        pollTimer = setInterval(function () { poll(res.j.jid); }, 2000);
        tickTimer = setInterval(function () { metaEl.textContent = metaText(); }, 1000);
      })
      .catch(function (e2) {
        if (btn) { btn.disabled = false; btn.textContent = "Generate from image"; }
        err.style.display = "";
        err.textContent = e2.message;
      });
  });
})();
