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
  var btnUpdate = document.getElementById("btn-update");
  var btnCheck = document.getElementById("btn-check");

  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

  function setInstallDisabled(disabled, reason) {
    if (!btnUpdate) return;
    btnUpdate.disabled = disabled;
    btnUpdate.title = reason || "";
  }

  var resultBadge = null;   // verdict from the last finished update run

  function check() {
    stateEl.textContent = "checking…";
    fetch("/api/update-check", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error && !d.remote) {
          stateEl.textContent = "check failed: " + d.error;
          setInstallDisabled(false, "Could not verify the latest version - install anyway");
          return;
        }
        if (d.running) {
          stateEl.innerHTML = '<span class="sevbadge sev-medium">update running…</span>';
          setInstallDisabled(true, "An update is currently in progress");
        } else if (d.up_to_date) {
          stateEl.innerHTML = '<span class="sevbadge sev-low">up to date</span> <span class="mono">' + esc(d.remote) + "</span>";
          setInstallDisabled(true, "You are already running the latest version");
        } else if (d.remote) {
          stateEl.innerHTML = '<span class="sevbadge sev-high">update available</span> remote <span class="mono">' + esc(d.remote) + "</span>";
          setInstallDisabled(false, "Install the latest version from GitHub");
        } else {
          stateEl.textContent = "remote version unknown";
          setInstallDisabled(false, "Could not determine the remote version - install anyway");
        }
        if (resultBadge) {
          stateEl.innerHTML = resultBadge;
          resultBadge = null;
        }
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
      .catch(function () {
        stateEl.textContent = "check failed (network error)";
        setInstallDisabled(false, "Could not reach the update service - install anyway");
      });
  }

  function pollLog() {
    fetch("/api/update-status", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (logEl) logEl.textContent = d.log || "(no output yet)";
        if (d.running) {
          stateEl.innerHTML = '<span class="sevbadge sev-medium">update running…</span>';
          setInstallDisabled(true, "An update is currently in progress");
          setTimeout(pollLog, 2500);
        } else {
          var lg = d.log || "";
          if (lg.indexOf("RESULT: UPDATE FAILED") !== -1) {
            resultBadge = '<span class="sevbadge sev-high">update FAILED</span> <span class="muted">the site keeps running the current build - see the log below</span>';
            setInstallDisabled(false);
          } else if (lg.indexOf("RESULT: UPDATE INCOMPLETE") !== -1) {
            resultBadge = '<span class="sevbadge sev-medium">update incomplete</span> <span class="muted">restart required - see the log below</span>';
            setInstallDisabled(false);
          } else if (lg.indexOf("RESULT: UPDATE SUCCESSFUL") !== -1) {
            resultBadge = '<span class="sevbadge sev-low">update successful</span>';
          }
          check();
        }
      })
      .catch(function () { setTimeout(pollLog, 4000); });
  }

  if (btnCheck) btnCheck.addEventListener("click", check);
  if (btnUpdate) {
    btnUpdate.addEventListener("click", function () {
      if (btnUpdate.disabled) return;
      var msg = btnUpdate.getAttribute("data-confirm") || "Install update?";
      if (!window.confirm(msg)) return;
      btnUpdate.disabled = true;
      fetch("/api/update-run", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": csrf }
      }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (!res.ok) {
            setInstallDisabled(false);
            window.alert("Update failed to start: " + (res.j.error || "unknown error"));
            return;
          }
          setInstallDisabled(true, "An update is currently in progress");
          stateEl.innerHTML = '<span class="sevbadge sev-medium">update running…</span>';
          pollLog();
        })
        .catch(function () {
          setInstallDisabled(false);
          window.alert("Network error while starting update.");
        });
    });
  }

  check();
})();
