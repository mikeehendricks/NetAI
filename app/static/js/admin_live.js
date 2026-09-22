/* Admin realtime sessions + world map (polls /api/live-sessions every 10s) */
(function () {
  "use strict";
  var mapSvg = document.getElementById("livemap");
  if (!mapSvg) return;
  var NS = "http://www.w3.org/2000/svg";
  var W = 720, H = 300;

  /* real coastlines loaded from world-land.js (Natural Earth, public domain) */
  function proj(lon, lat) {
    return [ (lon + 180) / 360 * W, (90 - lat) / 180 * H ];
  }
  function initMap() {
    var bg = document.createElementNS(NS, "rect");
    bg.setAttribute("width", W); bg.setAttribute("height", H); bg.setAttribute("fill", "#0a1322");
    bg.setAttribute("rx", 10);
    mapSvg.appendChild(bg);
    for (var gx = 0; gx <= W; gx += W / 12) {
      var l = document.createElementNS(NS, "line");
      l.setAttribute("x1", gx); l.setAttribute("x2", gx); l.setAttribute("y1", 0); l.setAttribute("y2", H);
      l.setAttribute("stroke", "#14213a"); l.setAttribute("stroke-width", 0.7);
      mapSvg.appendChild(l);
    }
    for (var gy = 0; gy <= H; gy += H / 6) {
      var l2 = document.createElementNS(NS, "line");
      l2.setAttribute("x1", 0); l2.setAttribute("x2", W); l2.setAttribute("y1", gy); l2.setAttribute("y2", gy);
      l2.setAttribute("stroke", "#14213a"); l2.setAttribute("stroke-width", 0.7);
      mapSvg.appendChild(l2);
    }
    (window.NETAI_LAND || []).forEach(function (ring) {
      var pts = ring.map(function (p) { return proj(p[0], p[1]).join(","); }).join(" ");
      var pg = document.createElementNS(NS, "polygon");
      pg.setAttribute("points", pts);
      pg.setAttribute("fill", "#182540");
      pg.setAttribute("stroke", "#24365c");
      pg.setAttribute("stroke-width", 0.8);
      mapSvg.appendChild(pg);
    });
  }
  initMap();
  var dotsG = document.createElementNS(NS, "g");
  mapSvg.appendChild(dotsG);

  function renderMap(points) {
    while (dotsG.firstChild) dotsG.removeChild(dotsG.firstChild);
    points.forEach(function (p) {
      if (p.lat == null || p.lon == null) return;
      var xy = proj(p.lon, p.lat);
      var c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", xy[0]); c.setAttribute("cy", xy[1]); c.setAttribute("r", 5);
      c.setAttribute("fill", "rgba(34,211,238,.25)");
      dotsG.appendChild(c);
      var c2 = document.createElementNS(NS, "circle");
      c2.setAttribute("cx", xy[0]); c2.setAttribute("cy", xy[1]); c2.setAttribute("r", 2.4);
      c2.setAttribute("fill", "#22d3ee");
      dotsG.appendChild(c2);
      var t = document.createElementNS(NS, "title");
      t.textContent = (p.username || "?") + " — " + (p.location || p.ip);
      c.appendChild(t); c2.appendChild(t);
    });
  }

  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
  function ago(iso) {
    var t = new Date(iso).getTime();
    if (!t) return "";
    var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    return Math.floor(s / 3600) + "h ago";
  }

  function poll() {
    fetch("/api/live-sessions", { headers: { "Accept": "application/json" }, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        var tb = document.querySelector("#livetbl tbody");
        tb.innerHTML = "";
        if (!data.sessions.length) tb.innerHTML = '<tr><td colspan="5" class="muted">No active sessions in the last 5 minutes.</td></tr>';
        data.sessions.forEach(function (s) {
          var tr = document.createElement("tr");
          tr.innerHTML = "<td><strong>" + esc(s.username) + "</strong></td>" +
            '<td class="mono">' + esc(s.ip) + "</td><td>" + esc(s.location) + "</td>" +
            '<td class="muted">' + esc(ago(s.last_seen)) + "</td>" +
            '<td class="muted small">' + esc(s.agent) + "</td>";
          tb.appendChild(tr);
        });
        var cnt = document.getElementById("livecount");
        if (cnt) cnt.textContent = data.sessions.length;
        var hb = document.querySelector("#historytbl tbody");
        hb.innerHTML = "";
        data.history.forEach(function (h) {
          var tr = document.createElement("tr");
          var d = new Date(h.ts);
          tr.innerHTML = "<td>" + esc(h.username) + "</td>" +
            '<td class="muted">' + esc(d.toISOString ? d.toISOString().replace("T", " ").slice(0, 16) : h.ts) + "</td>" +
            '<td class="mono">' + esc(h.ip) + "</td><td>" + esc(h.location) + "</td>";
          hb.appendChild(tr);
        });
        var pts = data.sessions.filter(function (s) { return s.lat != null; });
        if (!pts.length) pts = data.history.filter(function (h) { return h.lat != null; }).slice(0, 30);
        renderMap(pts);
        var empty = document.getElementById("mapempty");
        if (empty) empty.textContent = pts.length ? "" : "No geolocatable public IPs yet (private/local accesses are not plotted).";
      })
      .catch(function () {
        var tb = document.querySelector("#livetbl tbody");
        if (tb) tb.innerHTML = '<tr><td colspan="5" class="muted">Polling failed — will retry.</td></tr>';
      });
  }
  poll();
  setInterval(poll, 10000);
})();
