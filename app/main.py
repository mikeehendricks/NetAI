"""Main app: dashboard, config upload/analysis, results, topology, exec summary, downloads."""
import difflib
import ipaddress
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request,
    send_file, session, url_for,
)
from markupsafe import escape
from werkzeug.utils import secure_filename

from .analysis import engine
from .analysis import topology as topo_mod
from .analysis.summary import to_markdown
from .models import ConfigFile, Project, db, utcnow
from .security import audit, check_csrf, client_ip, login_required

bp = Blueprint("main", __name__)


@bp.before_app_request
def force_password_reset():
    if (
        session.get("uid")
        and request.endpoint not in ("auth.account", "auth.logout", "static")
        and request.method == "GET"
    ):
        from .auth import current_user

        u = current_user()
        if u and u.must_reset:
            return redirect(url_for("auth.account"))


@bp.route("/favicon.ico")
def favicon():
    from flask import current_app, send_from_directory

    return send_from_directory(current_app.static_folder, "img/logo.svg",
                               mimetype="image/svg+xml", max_age=86400)


@bp.route("/")
@login_required
def index():
    from .auth import current_user

    u = current_user()
    q = Project.query
    if session.get("role") != "admin":
        q = q.filter(Project.user_id == u.id)
    projects = q.order_by(Project.created_at.desc()).limit(50).all()
    # quick stats for the current user
    my_projects = Project.query.filter(Project.user_id == u.id).count()
    my_findings = 0
    for p in Project.query.filter(Project.user_id == u.id).all():
        my_findings += len(p.findings)
    return render_template("index.html", projects=projects, my_projects=my_projects,
                           my_findings=my_findings)


@bp.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze_upload():
    cfg = current_app.config
    if request.method == "POST":
        if not check_csrf():
            abort(400, "Invalid CSRF token")
        files = request.files.getlist("configs")
        pasted = (request.form.get("config_text") or "").strip()
        if (not files or all(f.filename in ("", None) for f in files)) and not pasted:
            flash("Upload at least one configuration file, or paste a configuration in the box below the upload field.", "warn")
            return redirect(url_for("main.analyze_upload"))
        if len(files) > cfg["MAX_UPLOAD_FILES"]:
            flash(f"Too many files (max {cfg['MAX_UPLOAD_FILES']}).", "warn")
            return redirect(url_for("main.analyze_upload"))

        items, rejected = [], []
        for f in files:
            if not f.filename:
                continue
            orig = secure_filename(f.filename)[:200] or "config.txt"
            ext = Path(orig).suffix.lower()
            if ext not in cfg["ALLOWED_UPLOAD_EXT"]:
                rejected.append(f"{orig}: unsupported extension")
                continue
            data = f.read(cfg["MAX_CONTENT_LENGTH"] + 1)
            if len(data) > cfg["MAX_CONTENT_LENGTH"]:
                rejected.append(f"{orig}: exceeds {cfg['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB limit")
                continue
            if b"\x00" in data[:8192]:
                rejected.append(f"{orig}: binary files are not accepted")
                continue
            text = data.decode("utf-8", "replace")
            if len(text) > 4_000_000:
                rejected.append(f"{orig}: too large (>4M chars)")
                continue
            items.append({"name": orig, "text": text})
        if pasted:
            if len(pasted) > 4_000_000:
                rejected.append("pasted config: too large (>4M chars)")
            else:
                items.append({"name": "pasted-config.txt", "text": pasted})
        if not items:
            flash("No valid configuration files. " + " ".join(rejected), "danger")
            return redirect(url_for("main.analyze_upload"))

        # ---- run the analysis engine
        result = engine.analyze_files(items)

        proj = Project(
            name=(request.form.get("project_name") or "").strip()[:120] or f"Analysis {utcnow():%Y-%m-%d %H:%M}",
            user_id=session["uid"],
            risk_score=result["score"], grade=result["grade"],
            findings_json=json.dumps(result["findings"]),
            summary_json=json.dumps(result["summary"]),
            devices_json=json.dumps([
                {k: v for k, v in d.items() if k not in ("raw",)} | {"kind": _kind_of(d)}
                for d in result["devices"]
            ]),
        )
        db.session.add(proj)
        db.session.flush()
        updir = Path(cfg["UPLOAD_FOLDER"]) / f"project{proj.id}"
        updir.mkdir(parents=True, exist_ok=True)
        for it, pf in zip(items, result["per_file"]):
            stored = uuid.uuid4().hex + ".cfg"
            (updir / stored).write_text(it["text"], encoding="utf-8")
            try:
                (updir / stored).chmod(0o600)
            except OSError:
                pass
            db.session.add(ConfigFile(
                project_id=proj.id, orig_name=it["name"], stored_name=stored,
                vendor=pf["vendor"], hostname=pf["device"].get("hostname", ""),
                size=len(it["text"]), sha256=pf["device"].get("sha256", ""),
                device_json=json.dumps({k: v for k, v in pf["device"].items() if k != "raw"}),
                topo_json=json.dumps({}),
            ))
        db.session.commit()
        audit("project.create", f"{proj.name} ({len(items)} files, score {proj.risk_score})")
        flash(f"Analysis complete: {len(result['findings'])} findings, risk score {result['score']}/100 (grade {result['grade']}).", "success")
        return redirect(url_for("main.project", pid=proj.id))

    return render_template("analyze.html", max_files=cfg["MAX_UPLOAD_FILES"],
                           max_mb=cfg["MAX_CONTENT_LENGTH"] // (1024 * 1024))


def _kind_of(d):
    from .analysis.topology import _device_kind

    return _device_kind(d)


def _get_project_or_403(pid):
    from .auth import current_user

    proj = db.session.get(Project, pid)
    if proj is None:
        abort(404)
    u = current_user()
    if proj.user_id != u.id and session.get("role") != "admin":
        abort(403)
    return proj


@bp.route("/project/<int:pid>")
@login_required
def project(pid):
    proj = _get_project_or_403(pid)
    findings = proj.findings
    devices = proj.devices
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    sev_filter = request.args.get("sev", "")
    dev_filter = request.args.get("dev", "")
    shown = [f for f in findings
             if (not sev_filter or f["severity"] == sev_filter)
             and (not dev_filter or f.get("device") == dev_filter)]
    return render_template("project.html", p=proj, findings=shown, counts=counts,
                           all_findings=findings, devices=devices,
                           sev_filter=sev_filter, dev_filter=dev_filter,
                           sev_order=["critical", "high", "medium", "low", "info"])


# ---------------------------------------------------------------- config generator
def _topo_store():
    p = Path(current_app.config["UPLOAD_FOLDER"]).parent / "topo_configs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _prune_topo_results():
    cutoff = time.time() - 24 * 3600
    try:
        for f in _topo_store().glob("*.json"):
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
    except OSError:
        pass


@bp.route("/tools/topo-config", methods=["GET", "POST"])
@login_required
def topo_config():
    from .analysis import topo_config as gen_mod

    cfg = current_app.config
    if request.method == "GET":
        _prune_topo_results()
        projects = [{"id": p.id, "name": p.name} for p in Project.query.order_by(Project.created_at.desc()).limit(30)]
        # Recent generations for this user: a long local-AI run can outlive the
        # Cloudflare/browser timeout, and the result id is otherwise only delivered
        # by the POST redirect - this list makes those completed results recoverable.
        recent = []
        try:
            for f in sorted(_topo_store().glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if d.get("user_id") != session.get("uid"):
                    continue
                recent.append({"rid": f.stem, "note": d.get("note", ""), "n": len(d.get("files", [])),
                               "when": int(d.get("created") or f.stat().st_mtime),
                               "label": time.strftime("%d %b %H:%M", time.localtime(int(d.get("created") or f.stat().st_mtime)))})
                if len(recent) >= 5:
                    break
        except OSError:
            pass
        return render_template("topo_config.html", vision_ok=gen_mod.vision_available(cfg),
                               projects=projects, preselect=request.args.get("project", type=int),
                               recent=recent)

    # ---------------- POST: generate ----------------
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    source = request.form.get("source") or "image"
    topo, note = None, ""
    if source == "project":
        proj = _get_project_or_403(request.form.get("project_id", type=int) or 0)
        topo = topo_mod.build_topology(proj.devices) if proj.devices else {"nodes": [], "links": []}
        note = f"Generated from project '{proj.name}'."
    else:
        f = request.files.get("topo_image")
        data = f.read(8 * 1024 * 1024 + 1) if f and f.filename else b""
        if not data:
            flash("Choose a topology image (PNG or JPEG) first.", "warn")
            return redirect(url_for("main.topo_config"))
        if len(data) > 8 * 1024 * 1024:
            flash("That image is larger than 8 MB. Export it at a lower resolution.", "warn")
            return redirect(url_for("main.topo_config"))
        sniffed = gen_mod.sniff_image(data)
        if not sniffed:
            flash("That file is not a PNG or JPEG image.", "danger")
            return redirect(url_for("main.topo_config"))
        try:
            topo = gen_mod.extract_topology_from_image(cfg, data, sniffed[0])
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("main.topo_config"))
        note = f"Recognized {len(topo['devices'])} device(s) and {len(topo['links'])} link(s) from the image - review before use."
    try:
        files = gen_mod.generate_from_topology(topo)
    except Exception:
        current_app.logger.exception("topo-config generation failed")
        flash("Could not generate configurations from that topology.", "danger")
        return redirect(url_for("main.topo_config"))
    if not files:
        flash("No devices were found in that topology to generate configs for.", "warn")
        return redirect(url_for("main.topo_config"))
    rid = uuid.uuid4().hex
    record = {"user_id": session.get("uid"), "created": time.time(), "note": note, "files": files}
    (_topo_store() / f"{rid}.json").write_text(json.dumps(record), encoding="utf-8")
    audit("tool.topo_config", f"{source}: {len(files)} config file(s)")
    flash(f"{note} Generated {len(files)} configuration file(s).", "success")
    return redirect(url_for("main.topo_config_result", rid=rid))


def _topo_result_or_403(rid):
    if not re.fullmatch(r"[a-f0-9]{32}", rid or ""):
        abort(404)
    p = _topo_store() / f"{rid}.json"
    if not p.exists():
        abort(404)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        abort(404)
    if data.get("user_id") != session.get("uid") and session.get("role") != "admin":
        abort(403)
    return data


@bp.route("/tools/topo-config/results/<rid>")
@login_required
def topo_config_result(rid):
    data = _topo_result_or_403(rid)
    return render_template("topo_config_result.html", rid=rid, note=data.get("note", ""), files=data["files"])


@bp.route("/tools/topo-config/results/<rid>/files/<int:idx>")
@login_required
def topo_config_file(rid, idx):
    data = _topo_result_or_403(rid)
    if idx < 0 or idx >= len(data["files"]):
        abort(404)
    f = data["files"][idx]
    import io as _io

    return send_file(_io.BytesIO(f["config"].encode("utf-8")), as_attachment=True,
                     download_name=secure_filename(f["filename"]) or f"device-{idx}.cfg",
                     mimetype="text/plain")


@bp.route("/tools/topo-config/results/<rid>/bundle.zip")
@login_required
def topo_config_zip(rid):
    data = _topo_result_or_403(rid)
    import io as _io
    import zipfile as _zip

    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as z:
        for i, f in enumerate(data["files"]):
            z.writestr(secure_filename(f["filename"]) or f"device-{i}.cfg", f["config"])
        z.writestr("README.txt",
                   "Generated by NetAI from the reviewed topology.\n"
                   "Review every file before applying: addresses, routing and\n"
                   "credentials must match your own standards.\n")
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"netai-configs-{rid[:8]}.zip",
                     mimetype="application/zip")


@bp.route("/project/<int:pid>/topology")
@login_required
def topology(pid):
    proj = _get_project_or_403(pid)
    files = proj.files
    devs = [f.device for f in files]
    topo = topo_mod.build_topology(devs) if devs else {"nodes": [], "links": []}
    return render_template("topology.html", p=proj, topo=topo)


def _fresh_summary(proj):
    """Return the executive summary, regenerating it when it was produced by an
    older app version. Keeps improved business-impact wording flowing to
    existing projects without re-uploading; AI-enhanced text is preserved."""
    from .analysis import summary as summary_mod

    s = proj.summary or {}
    if s.get("gen") == summary_mod.SUMMARY_GEN or not proj.findings:
        return s
    s2 = summary_mod.build(s.get("inventory_doc", ""), proj.devices, proj.findings,
                           proj.risk_score, proj.grade)
    if s.get("ai_markdown"):
        s2["ai_markdown"] = s["ai_markdown"]      # never lose AI-enhanced content
    proj.summary_json = json.dumps(s2)
    db.session.commit()
    return s2


@bp.route("/project/<int:pid>/summary")
@login_required
def summary_view(pid):
    proj = _get_project_or_403(pid)
    s = _fresh_summary(proj)
    md_html = None
    if proj.ai_enhanced and s.get("ai_markdown"):
        from .markdown_mini import md_to_html

        md_html = md_to_html(s["ai_markdown"])
    from .analysis import ai as ai_mod

    ai_ready = ai_mod.ai_available(current_app.config)
    return render_template("summary.html", p=proj, s=s, md_html=md_html, ai_ready=ai_ready)


@bp.route("/project/<int:pid>/summary/enhance", methods=["POST"])
@login_required
def summary_enhance(pid):
    proj = _get_project_or_403(pid)
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    from .analysis import ai as ai_mod

    cfg = current_app.config
    if not ai_mod.ai_available(cfg):
        flash("AI enhancement is not configured. Set AI_PROVIDER and the matching API key in the .env file.", "warn")
        return redirect(url_for("main.summary_view", pid=pid))
    md = to_markdown(_fresh_summary(proj))
    polished = ai_mod.enhance(cfg, proj.findings, md)
    if polished:
        s = proj.summary
        s["ai_markdown"] = polished
        proj.summary_json = json.dumps(s)
        proj.ai_enhanced = True
        db.session.commit()
        flash("Executive summary enhanced with AI.", "success")
    else:
        flash("AI enhancement failed (check API key/connectivity). The deterministic summary is shown.", "warn")
    return redirect(url_for("main.summary_view", pid=pid))


@bp.route("/project/<int:pid>/delete", methods=["POST"])
@login_required
def project_delete(pid):
    proj = _get_project_or_403(pid)
    if not check_csrf():
        abort(400, "Invalid CSRF token")
    import shutil

    shutil.rmtree(Path(current_app.config["UPLOAD_FOLDER"]) / f"project{pid}", ignore_errors=True)
    db.session.delete(proj)
    db.session.commit()
    audit("project.delete", proj.name)
    flash("Project deleted.", "success")
    return redirect(url_for("main.index"))


# --------------------------------------------------------------------------- downloads
def _project_file_or_403(pid, fid):
    proj = _get_project_or_403(pid)
    cf = db.session.get(ConfigFile, fid)
    if cf is None or cf.project_id != pid:
        abort(404)
    return proj, cf


def _raw_text(cf):
    path = Path(current_app.config["UPLOAD_FOLDER"]) / f"project{cf.project_id}" / cf.stored_name
    if not path.resolve().is_relative_to((Path(current_app.config["UPLOAD_FOLDER"])).resolve()):
        abort(404)   # path traversal guard
    if not path.exists():
        abort(404)
    return path.read_text(encoding="utf-8", errors="replace")


@bp.route("/project/<int:pid>/file/<int:fid>/original")
@login_required
def file_original(pid, fid):
    proj, cf = _project_file_or_403(pid, fid)
    return send_file(Path(current_app.config["UPLOAD_FOLDER"]) / f"project{pid}" / cf.stored_name,
                     as_attachment=True, download_name=cf.orig_name)


@bp.route("/project/<int:pid>/file/<int:fid>/improved")
@login_required
def file_improved(pid, fid):
    proj, cf = _project_file_or_403(pid, fid)
    raw = _raw_text(cf)
    vendor, parsed = engine.parse_file(raw)
    mod = engine.VENDOR_MODULES.get(vendor)
    if not mod:
        flash("Vendor unknown - cannot generate improved config.", "warn")
        return redirect(url_for("main.project", pid=pid))
    parsed["vendor"] = vendor
    try:
        fnd = mod.analyze(parsed)
    except Exception:
        fnd = []
    improved = mod.improve(parsed, fnd)
    import io

    buf = io.BytesIO(improved.encode("utf-8"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", cf.orig_name)
    return send_file(buf, as_attachment=True, download_name=f"improved_{name}", mimetype="text/plain")


@bp.route("/project/<int:pid>/file/<int:fid>/diff")
@login_required
def file_diff(pid, fid):
    proj, cf = _project_file_or_403(pid, fid)
    raw = _raw_text(cf)
    vendor, parsed = engine.parse_file(raw)
    mod = engine.VENDOR_MODULES.get(vendor)
    if not mod:
        abort(404)
    parsed["vendor"] = vendor
    try:
        fnd = mod.analyze(parsed)
    except Exception:
        fnd = []
    improved = mod.improve(parsed, fnd)
    diff = difflib.unified_diff(raw.splitlines(), improved.splitlines(),
                                fromfile="original", tofile="NetAI improved", lineterm="")
    html = render_template("_diff.html", diff=list(diff)[:2000], cf=cf)
    return html


@bp.route("/project/<int:pid>/summary.md")
@login_required
def summary_md(pid):
    proj = _get_project_or_403(pid)
    s = _fresh_summary(proj)
    md = s.get("ai_markdown") or to_markdown(s)
    import io

    return send_file(io.BytesIO(md.encode("utf-8")), as_attachment=True,
                     download_name=f"executive_summary_{pid}.md", mimetype="text/markdown")
