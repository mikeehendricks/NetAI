// NetAI shared UI behaviours (CSP-safe: no inline handlers)
(function () {
  "use strict";

  // confirmation dialogs
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (f.classList && f.classList.contains("confirm-form")) {
      var msg = f.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(msg)) e.preventDefault();
    }
  });
  document.addEventListener("click", function (e) {
    var b = e.target.closest(".confirm-btn");
    if (b) {
      var msg = b.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(msg)) e.preventDefault();
    }
    var pb = e.target.closest(".print-btn");
    if (pb) window.print();
  });

  // double-submit guard: once a form submits, disable its submit button.
  // Runs in the bubble phase AFTER the confirm handlers above, so cancelled
  // dialogs (defaultPrevented) never disable anything.
  document.addEventListener("submit", function (e) {
    if (e.defaultPrevented) return;
    var f = e.target;
    if (!f || !f.matches || !f.matches("form")) return;
    var ae = document.activeElement;
    var btn = (ae && ae.form === f && ae.type === "submit") ? ae
      : f.querySelector('button[type="submit"], button:not([type])');
    if (!btn) return;
    if (btn.disabled) { e.preventDefault(); return; }
    setTimeout(function () {
      btn.disabled = true;
      if (!btn.getAttribute("data-origlabel")) btn.setAttribute("data-origlabel", btn.textContent);
      btn.textContent = btn.getAttribute("data-busylabel") || "Working\u2026";
    }, 0);
  });
  // restore buttons when the user navigates back / returns via bfcache
  window.addEventListener("pageshow", function () {
    document.querySelectorAll("button[data-origlabel]").forEach(function (b) {
      b.disabled = false;
      b.textContent = b.getAttribute("data-origlabel");
    });
  });

  // analyze form: require at least one file OR pasted text before submitting
  var aform = document.getElementById("analyze-form");
  if (aform) {
    aform.addEventListener("submit", function (e) {
      var fi = document.getElementById("configs");
      var ta = document.getElementById("config_text");
      var has = (fi && fi.files && fi.files.length > 0) || (ta && ta.value.trim());
      if (!has) {
        e.preventDefault();
        var err = document.getElementById("analyze-error");
        if (err) {
          err.style.display = "";
          err.textContent = "Choose at least one configuration file, or paste a configuration first.";
        }
      }
    });
  }

  // animate bar charts
  document.querySelectorAll(".bar-fill[data-w]").forEach(function (el) {
    requestAnimationFrame(function () {
      el.style.transition = "width .8s ease";
      el.style.width = el.getAttribute("data-w") + "%";
    });
  });

  // upload file list preview
  var inp = document.getElementById("configs");
  if (inp) {
    inp.addEventListener("change", function () {
      var list = document.getElementById("filelist");
      if (!list) return;
      list.textContent = "";
      Array.prototype.forEach.call(inp.files, function (f) {
        var d = document.createElement("div");
        d.textContent = "• " + f.name + " (" + f.size + " bytes)";
        list.appendChild(d);
      });
    });
  }
})();
