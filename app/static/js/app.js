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
