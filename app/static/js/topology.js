/* NetAI low-level topology renderer (vanilla JS + SVG, CSP-safe) */
(function () {
  "use strict";
  var dataEl = document.getElementById("topo-data");
  var svg = document.getElementById("topo-svg");
  if (!dataEl || !svg) return;
  var graph = JSON.parse(dataEl.textContent);
  var NS = "http://www.w3.org/2000/svg";

  /* ---------------- layout: force-directed, deterministic seed ---------------- */
  var nodes = graph.nodes.map(function (n, i) {
    return { id: n.id, kind: n.kind, label: n.label, meta: n.meta || {},
             x: 400 + 260 * Math.cos(i * 2.399963), y: 300 + 200 * Math.sin(i * 2.399963),
             vx: 0, vy: 0, el: null };
  });
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  var links = graph.links.filter(function (l) { return byId[l.source] && byId[l.target]; });

  function widthOf(n) { return n.kind === "subnet" || n.kind === "vlan" ? 150 : n.kind === "cloud" ? 130 : 150; }
  function heightOf(n) { return n.kind === "subnet" || n.kind === "vlan" ? 40 : n.kind === "cloud" ? 70 : 54; }

  function forceLayout() {
  for (var iter = 0; iter < 320; iter++) {
    // repulsion
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var a = nodes[i], b = nodes[j];
        var dx = b.x - a.x, dy = b.y - a.y;
        var d2 = dx * dx + dy * dy + 40;
        var f = 26000 / d2;
        var d = Math.sqrt(d2);
        var fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    // springs
    links.forEach(function (l) {
      var a = byId[l.source], b = byId[l.target];
      var dx = b.x - a.x, dy = b.y - a.y;
      var d = Math.sqrt(dx * dx + dy * dy) || 1;
      var want = l.kind === "l2" ? 130 : 170;
      var f = (d - want) * 0.015;
      var fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    });
    // gravity to center + integrate
    nodes.forEach(function (n) {
      n.vx += (400 - n.x) * 0.002; n.vy += (280 - n.y) * 0.002;
      n.vx *= 0.85; n.vy *= 0.85;
      n.x += Math.max(-14, Math.min(14, n.vx));
      n.y += Math.max(-14, Math.min(14, n.vy));
    });
  }
  }

  /* ------------- tree layout (DEFAULT): WAN on top, hierarchy below --------
     BFS from the Internet/WAN cloud (or the best-connected device) builds the
     levels; leaves are packed left-to-right and every parent is centred over
     its children, giving the classic ISP-tree reading order.               */
  function treeLayout() {
    if (!nodes.length) return;
    var adj = {}, prio = { cloud: 0, firewall: 1, router: 2, switch: 3, device: 4, subnet: 5, vlan: 6 };
    nodes.forEach(function (n) { adj[n.id] = []; });
    links.forEach(function (l) {
      if (adj[l.source] && adj[l.target]) { adj[l.source].push(l.target); adj[l.target].push(l.source); }
    });
    function rank(id) {
      var n = byId[id];
      return (prio[n.kind] !== undefined ? prio[n.kind] : 5) + "/" + n.label;
    }
    nodes.forEach(function (n) {
      adj[n.id].sort(function (a, b) { return rank(a) < rank(b) ? -1 : 1; });
    });
    var roots = nodes.filter(function (n) { return n.kind === "cloud"; }).map(function (n) { return n.id; });
    if (!roots.length) {
      var cands = nodes.filter(function (n) {
        return n.kind === "router" || n.kind === "firewall" || n.kind === "switch";
      }).sort(function (a, b) { return adj[b.id].length - adj[a.id].length; });
      roots = [cands.length ? cands[0].id : nodes[0].id];
    }
    var parent = {}, depth = {}, visited = {}, queue = [];
    roots.forEach(function (r) { visited[r] = true; depth[r] = 0; parent[r] = null; queue.push(r); });
    function bfs() {
      while (queue.length) {
        var id = queue.shift();
        adj[id].forEach(function (m) {
          if (!visited[m]) { visited[m] = true; parent[m] = id; depth[m] = depth[id] + 1; queue.push(m); }
        });
      }
    }
    bfs();
    nodes.forEach(function (n) {          // disconnected components become extra trees
      if (!visited[n.id]) { visited[n.id] = true; parent[n.id] = null; depth[n.id] = 0; roots.push(n.id); queue.push(n.id); }
    });
    bfs();
    var children = {}, posX = {};
    nodes.forEach(function (n) { children[n.id] = []; });
    nodes.forEach(function (n) { if (parent[n.id]) children[parent[n.id]].push(n.id); });
    var cursor = 0;
    function wOf(id) { return widthOf(byId[id]); }
    function place(id) {
      var kids = children[id];
      if (!kids.length) { posX[id] = cursor + wOf(id) / 2; cursor += wOf(id) + 64; return; }
      var first = null, last = null;
      kids.forEach(function (k) { place(k); if (first === null) first = posX[k]; last = posX[k]; });
      posX[id] = (first + last) / 2;
    }
    roots.forEach(function (r, i) { if (i > 0) cursor += 90; place(r); });
    nodes.forEach(function (n) {
      n.x = posX[n.id] !== undefined ? posX[n.id] : 400 + Math.random() * 40;
      n.y = 80 + depth[n.id] * 135;
    });
  }

  function applyLayout(mode) {
    if (mode === "force") forceLayout(); else treeLayout();
    nodes.forEach(function (n) { redrawNode(n); });
    fit();
  }
  treeLayout();   // default view

  /* ---------------- svg helpers ---------------- */
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    (parent || svg).appendChild(e);
    return e;
  }
  function txt(x, y, s, cls, anchor, parent) {
    var t = el("text", { x: x, y: y, "class": cls || "tn", "text-anchor": anchor || "middle" }, parent);
    t.textContent = s;
    return t;
  }
  var KIND_COLOR = { firewall: "#f43f5e", router: "#6366f1", switch: "#22c55e",
                     cloud: "#64748b", subnet: "#22d3ee", vlan: "#facc15", device: "#94a3b8" };
  var vlanHue = {};
  (graph.vlan_colors || []).forEach(function (v, i) { vlanHue[v] = (i * 47 + 15) % 360; });

  var root = el("g", { "class": "topo-root" });
  var edgeG = el("g", { "class": "edges" }, root);
  var nodeG = el("g", { "class": "nodes" }, root);
  var info = document.createElement("div");
  info.className = "topo-info";
  var wrap = document.getElementById("topo-wrap");
  if (wrap) { info.style.cssText = "position:absolute;right:12px;top:12px;background:rgba(10,19,34,.95);border:1px solid #1f2d47;border-radius:10px;padding:10px 14px;font-size:12px;max-width:320px;display:none;color:#dbe4f3;line-height:1.5"; wrap.style.position = "relative"; wrap.appendChild(info); }

  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

  /* ---------------- edges ---------------- */
  links.forEach(function (l) {
    var a = byId[l.source], b = byId[l.target];
    var color = l.kind === "wan" ? "#64748b" : l.kind === "l2" && l.vlan ? "hsl(" + vlanHue[l.vlan] + " 80% 60%)" : "#2dd4bf";
    var line = el("line", { "class": "edge", stroke: color, "stroke-width": l.kind === "wan" ? 2 : 1.6,
                            "stroke-dasharray": l.kind === "wan" ? "6 4" : l.kind === "l2" ? "4 3" : "none",
                            opacity: .85 }, edgeG);
    var mid = el("g", { "class": "edgelabel" }, edgeG);
    var labelBg = el("rect", { rx: 4, fill: "#0a1322", opacity: .92 }, mid);
    var label = txt(0, 0, l.label + (l.ip ? " " + l.ip : ""), "edge-t", "middle", mid);
    label.setAttribute("fill", color);
    var lw = 100;
    try { lw = label.getComputedTextLength() + 12; } catch (e) {}
    function midPt() {
      var ax = a.x, ay = a.y, bx = b.x, by = b.y;
      var t = 0.62, mx = ax + (bx - ax) * t, my = ay + (by - ay) * t;   // nearer the child: stops label pile-ups at hubs
      mid.setAttribute("transform", "translate(" + mx + "," + my + ")");
      labelBg.setAttribute("x", -lw / 2); labelBg.setAttribute("y", -14);
      labelBg.setAttribute("width", lw); labelBg.setAttribute("height", 16);
      line.setAttribute("x1", ax); line.setAttribute("y1", ay);
      line.setAttribute("x2", bx); line.setAttribute("y2", by);
    }
    midPt();
    l._upd = midPt;
    var tip = "edge: " + l.label + (l.network ? "  |  " + l.network : "");
    line.addEventListener("mouseenter", function () { line.setAttribute("stroke-width", 3.4); showTip(tip); });
    line.addEventListener("mouseleave", function () { line.setAttribute("stroke-width", l.kind === "wan" ? 2 : 1.6); hideTip(); });
  });

  /* ---------------- nodes ---------------- */
  nodes.forEach(function (n) {
    var g = el("g", { "class": "node", cursor: "pointer" }, nodeG);
    var w = widthOf(n), h = heightOf(n), x = n.x - w / 2, y = n.y - h / 2;
    if (n.kind === "cloud") {
      var c = el("ellipse", { cx: n.x, cy: n.y, rx: w / 2, ry: h / 2, fill: "#0f1930",
        stroke: "#64748b", "stroke-width": 1.6, "stroke-dasharray": "6 4" }, g);
      txt(n.x, n.y - 4, n.label, "node-t", "middle", g);
      txt(n.x, n.y + 12, "upstream", "node-sub", "middle", g);
    } else if (n.kind === "subnet" || n.kind === "vlan") {
      var hue = n.meta.vlan ? "hsl(" + vlanHue[n.meta.vlan] + " 75% 55%)" : "#22d3ee";
      var r = el("rect", { x: x, y: y, width: w, height: h, rx: h / 2, fill: "#0f1930",
        stroke: hue, "stroke-width": 2 }, g);
      txt(n.x, n.y + 5, n.label, "node-t", "middle", g);
    } else {
      var color = KIND_COLOR[n.kind] || "#94a3b8";
      var rect = el("rect", { x: x, y: y, width: w, height: h, rx: 10, fill: "#101b31",
        stroke: color, "stroke-width": 2.2 }, g);
      var kindLabel = n.kind.toUpperCase();
      txt(n.x, n.y - 2, n.label, "node-t", "middle", g);
      txt(n.x, n.y + 14, kindLabel + (n.meta.vendor ? "  ·  " + n.meta.vendor : ""), "node-sub", "middle", g);
    }
    n.el = g;
    g.setAttribute("transform", "translate(0,0)");

    function showInfo() {
      if (!n.meta || (!n.meta.interfaces && !n.meta.routes && !n.meta.vlans)) { hideInfo(); return; }
      var html = "<strong>" + esc(n.label) + "</strong> <span style='color:#8294b0'>(" + esc(n.kind) + ")</span><br>";
      if (n.meta.interfaces) {
        html += "<em>interfaces</em><br>";
        n.meta.interfaces.slice(0, 10).forEach(function (i) {
          html += "&nbsp;• " + esc(i.name) + (i.ip ? " — " + esc(i.ip) : "") +
                  (i.vlan ? " vlan" + esc(i.vlan) : "") + (i.down ? " (down)" : "") + "<br>";
        });
        if (n.meta.interfaces.length > 10) html += "&nbsp;… +" + (n.meta.interfaces.length - 10) + " more<br>";
      }
      if (n.meta.routes && n.meta.routes.length) {
        html += "<em>routes</em><br>";
        n.meta.routes.slice(0, 6).forEach(function (r) { html += "&nbsp;→ " + esc(r.dst) + " via " + esc(r.via || "?") + "<br>"; });
      }
      info.innerHTML = html;
      info.style.display = "block";
    }
    function hideInfo() { info.style.display = "none"; }

    g.addEventListener("mouseenter", showInfo);
    g.addEventListener("mouseleave", hideInfo);

    // dragging
    var dragging = false, moved = false, sx = 0, sy = 0, ox = 0, oy = 0;
    g.addEventListener("mousedown", function (e) {
      dragging = true; moved = false; sx = e.clientX; sy = e.clientY; ox = n.x; oy = n.y;
      e.preventDefault(); e.stopPropagation();
    });
    window.addEventListener("mousemove", function (e) {
      if (!dragging) return;
      var scale = view.k || 1;
      n.x = ox + (e.clientX - sx) / scale;
      n.y = oy + (e.clientY - sy) / scale;
      moved = true;
      redrawNode(n);
    });
    window.addEventListener("mouseup", function () { dragging = false; });
  });

  function redrawNode(n) {
    var w = widthOf(n), h = heightOf(n);
    var g = n.el;
    var rect = g.querySelector("rect"), ell = g.querySelector("ellipse");
    if (rect && (n.kind === "subnet" || n.kind === "vlan")) {
      rect.setAttribute("x", n.x - w / 2); rect.setAttribute("y", n.y - h / 2);
    } else if (rect) {
      rect.setAttribute("x", n.x - w / 2); rect.setAttribute("y", n.y - h / 2);
    } else if (ell) {
      ell.setAttribute("cx", n.x); ell.setAttribute("cy", n.y);
    }
    var texts = g.querySelectorAll("text");
    if (texts.length) {
      if (n.kind === "cloud") {
        texts[0].setAttribute("x", n.x); texts[0].setAttribute("y", n.y - 4);
        if (texts[1]) { texts[1].setAttribute("x", n.x); texts[1].setAttribute("y", n.y + 12); }
      } else {
        texts[0].setAttribute("x", n.x); texts[0].setAttribute("y", n.y - 2);
        if (texts[1]) { texts[1].setAttribute("x", n.x); texts[1].setAttribute("y", n.y + (n.kind === "subnet" || n.kind === "vlan" ? 5 : 14)); }
      }
    }
    links.forEach(function (l) { if (l._upd) l._upd(); });
  }

  /* ---------------- pan & zoom ---------------- */
  var view = { x: 0, y: 0, k: 1 };
  function applyView() {
    root.setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")");
  }
  svg.addEventListener("wheel", function (e) {
    e.preventDefault();
    var factor = e.deltaY < 0 ? 1.12 : 0.89;
    var rect = svg.getBoundingClientRect();
    var mx = e.clientX - rect.left, my = e.clientY - rect.top;
    view.x = mx - (mx - view.x) * factor;
    view.y = my - (my - view.y) * factor;
    view.k = Math.max(0.25, Math.min(4, view.k * factor));
    applyView();
  }, { passive: false });
  var panning = false, px = 0, py = 0, pvx = 0, pvy = 0;
  svg.addEventListener("mousedown", function (e) { panning = true; px = e.clientX; py = e.clientY; pvx = view.x; pvy = view.y; });
  window.addEventListener("mousemove", function (e) {
    if (!panning) return;
    view.x = pvx + (e.clientX - px); view.y = pvy + (e.clientY - py); applyView();
  });
  window.addEventListener("mouseup", function () { panning = false; });

  // fit + centre content
  function fit() {
    if (!nodes.length) return;
    var minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    nodes.forEach(function (n) {
      minX = Math.min(minX, n.x - 90); minY = Math.min(minY, n.y - 60);
      maxX = Math.max(maxX, n.x + 90); maxY = Math.max(maxY, n.y + 60);
    });
    var rect = svg.getBoundingClientRect();
    var kx = rect.width / (maxX - minX), ky = rect.height / (maxY - minY);
    view.k = Math.max(0.25, Math.min(2.2, Math.min(kx, ky) * 0.95));
    view.x = (rect.width - (maxX - minX) * view.k) / 2 - minX * view.k;
    view.y = (rect.height - (maxY - minY) * view.k) / 2 - minY * view.k;
    applyView();
  }
  var fitBtn = document.getElementById("topo-fit");
  if (fitBtn) fitBtn.addEventListener("click", fit);
  var treeBtn = document.getElementById("topo-tree"), forceBtn = document.getElementById("topo-force");
  function setLayoutMode(m) {
    if (treeBtn) treeBtn.className = "btn btn-sm" + (m === "tree" ? " btn-primary" : "");
    if (forceBtn) forceBtn.className = "btn btn-sm" + (m === "force" ? " btn-primary" : "");
    applyLayout(m);
  }
  if (treeBtn) treeBtn.addEventListener("click", function () { setLayoutMode("tree"); });
  if (forceBtn) forceBtn.addEventListener("click", function () { setLayoutMode("force"); });
  setTimeout(fit, 30);

  // export
  var exportBtn = document.getElementById("topo-export");
  if (exportBtn) exportBtn.addEventListener("click", function () {
    var clone = svg.cloneNode(true);
    clone.setAttribute("width", 1200); clone.setAttribute("height", 800);
    var s = new XMLSerializer().serializeToString(clone);
    var blob = new Blob([s], { type: "image/svg+xml" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "network-topology.svg";
    document.body.appendChild(a); a.click(); a.remove();
  });

  // style injection (CSP-safe: stylesheet via DOM is same-origin)
  var st = document.createElementNS(NS, "style");
  st.textContent =
    ".tn{font:12px system-ui,sans-serif;fill:#dbe4f3}" +
    ".edge-t{font:10px ui-monospace,monospace}" +
    ".node-t{font:700 13px system-ui,sans-serif;fill:#e6eefb}" +
    ".node-sub{font:9px system-ui,sans-serif;fill:#8294b0;letter-spacing:.08em}" +
    ".node:hover rect,.node:hover ellipse{filter:brightness(1.25)}";
  svg.appendChild(st);

  function showTip(t) { if (info) { info.textContent = t; info.style.display = "block"; } }
  function hideTip() { if (info) info.style.display = "none"; }

  if (!nodes.length) {
    txt(400, 280, "No topology data — upload configs with interfaces/IPs.", "node-t");
  }
})();
