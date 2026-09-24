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

  function showUpdateDone(sha) {
    var done = document.getElementById("update-done");
    if (done) {
      done.style.display = "";
      done.innerHTML = '<strong>Update completed successfully.</strong> New build <span class="mono">' +
        esc(sha) + '</span> is live &mdash; reloading this page&hellip;';
    }
    if (stateEl) stateEl.innerHTML = '<span class="sevbadge sev-low">update successful</span>';
    // Wait until the restarted service answers, then reload so the page shows
    // the new build/version. Falls back to a plain reload after ~40s whatever happens.
    var tries = 0;
    (function ping() {
      tries++;
      fetch(window.location.pathname, { cache: "no-store", credentials: "same-origin" })
        .then(function (r) {
          if (r.ok || tries > 40) { window.location.reload(); return; }
          setTimeout(ping, 1000);
        })
        .catch(function () {
          if (tries > 40) { window.location.reload(); return; }
          setTimeout(ping, 1000);
        });
    })();
  }

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
        if (d.local) {
          localEl.textContent = d.local;
          // running process vs on-disk build: the footer stamp comes from the
          // RUNNING app; update-check reads the DISK. A mismatch means an
          // update pulled code but the service never restarted.
          var fEl = document.querySelector(".footer .mono");
          var fm = (fEl ? fEl.textContent : "").match(/build ([0-9a-f]{7,40})/);
          var runningSha = fm ? fm[1].slice(0, 7) : "";
          var staleBox = document.getElementById("update-stale");
          if (runningSha && d.local !== runningSha && !d.running) {
            if (staleBox) {
              staleBox.style.display = "";
              staleBox.innerHTML = '<strong>A newer build (' + esc(d.local) +
                ') is on disk but the site is still running ' + esc(runningSha) +
                '.</strong> Restart the service to load it: <span class="mono">sudo systemctl restart netai</span>' +
                ' &mdash; or click Install update to re-run the verified restart.';
            }
            setInstallDisabled(false);
          } else if (staleBox) {
            staleBox.style.display = "none";
          }
        }
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
          var mOk = lg.match(/RESULT: UPDATE SUCCESSFUL - running build ([0-9a-f]+)/i);
          if (lg.indexOf("RESULT: UPDATE FAILED") !== -1) {
            resultBadge = '<span class="sevbadge sev-high">update FAILED</span> <span class="muted">the site keeps running the current build - see the log below</span>';
            setInstallDisabled(false);
          } else if (lg.indexOf("RESULT: UPDATE INCOMPLETE") !== -1) {
            resultBadge = '<span class="sevbadge sev-medium">update incomplete</span> <span class="muted">restart required - see the log below</span>';
            setInstallDisabled(false);
          } else if (mOk) {
            resultBadge = '<span class="sevbadge sev-low">update successful</span>';
            showUpdateDone(mOk[1]);
            return;   // banner shown; page reloads once the new build answers
          } else if (lg.indexOf("update started") !== -1 && lg.indexOf("RESULT:") === -1) {
            resultBadge = '<span class="sevbadge sev-medium">update stalled</span> <span class="muted">the updater stopped without a verdict - see the log below, then retry</span>';
            setInstallDisabled(false);
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
