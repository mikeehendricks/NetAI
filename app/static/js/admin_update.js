/* Admin update page logic */
(function () {
  "use strict";
  var metaEl = document.getElementById("update-meta");
  if (!metaEl) return;
  var meta = JSON.parse(metaEl.textContent);
  var csrf = (document.querySelector('meta[name="csrf"]') || {}).content || "";

  var stateEl = document.getElementById("update-state");
  var localEl = document.getElementById("local-sha");
  var logEl = document.getElementById("updatelog");
  var commitBody = document.querySelector("#committbl tbody");

  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

  function check() {
    stateEl.textContent = "checking…";
    fetch("/api/update-check", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { stateEl.textContent = "check failed: " + d.error; return; }
        var behind = !d.up_to_date;
        stateEl.innerHTML = d.remote
          ? (behind ? '<span class="sevbadge sev-high">update available</span> remote <span class="mono">' + esc(d.remote) + "</span>"
                    : '<span class="sevbadge sev-low">up to date</span> <span class="mono">' + esc(d.remote) + "</span>")
          : "remote unknown";
        if (d.local) localEl.textContent = d.local;
        commitBody.innerHTML = "";
        if (!d.commits.length) commitBody.innerHTML = '<tr><td colspan="4" class="muted">No commits found.</td></tr>';
        d.commits.forEach(function (c) {
          var tr = document.createElement("tr");
          tr.innerHTML = '<td class="mono">' + esc(c.sha) + "</td><td>" + esc(c.message) +
            "</td><td>" + esc(c.author) + "</td><td class=\"muted\">" + esc((c.date || "").replace("T", " ").slice(0, 16)) + "</td>";
          commitBody.appendChild(tr);
        });
      })
      .catch(function () { stateEl.textContent = "check failed (network error)"; });
  }

  function pollLog() {
    fetch("/api/update-status", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (logEl) logEl.textContent = d.log || "(no output yet)";
        if (d.running) {
          stateEl.innerHTML = '<span class="sevbadge sev-medium">update running…</span>';
          setTimeout(pollLog, 2500);
        } else if (logEl && logEl.textContent.indexOf("(idle)") !== 0) {
          check();
        }
      })
      .catch(function () {});
  }

  var btnCheck = document.getElementById("btn-check");
  if (btnCheck) btnCheck.addEventListener("click", check);
  var btnUpdate = document.getElementById("btn-update");
  if (btnUpdate) {
    btnUpdate.addEventListener("click", function () {
      var msg = btnUpdate.getAttribute("data-confirm") || "Install update?";
      if (!window.confirm(msg)) return;
      btnUpdate.disabled = true;
      fetch("/api/update-run", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": csrf }
      }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          btnUpdate.disabled = false;
          if (!res.ok) { window.alert("Update failed to start: " + (res.j.error || "unknown error")); return; }
          stateEl.innerHTML = '<span class="sevbadge sev-medium">update running…</span>';
          pollLog();
        })
        .catch(function () { btnUpdate.disabled = false; window.alert("Network error while starting update."); });
    });
  }

  check();
})();
