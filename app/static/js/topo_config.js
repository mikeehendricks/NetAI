// Config generator: client-side pre-validation for the image form (CSP-safe).
(function () {
  "use strict";
  var form = document.getElementById("topoimg-form");
  if (!form) return;
  var inp = document.getElementById("topo_image");
  var err = document.getElementById("topoimg-error");
  form.addEventListener("submit", function (e) {
    if (e.defaultPrevented) return;
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
    }
  });
})();
