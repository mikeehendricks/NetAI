"""Main app: dashboard, config upload/analysis, results, topology, exec summary, downloads."""
import difflib
import ipaddress
import json
import os
import re
import secrets
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
        if not files or all(f.filename in ("", None) for f in files):
            flash("Select at least one configuration file.", "warn")
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
        if not items:
            flash("No valid configuration files uploaded. " + " ".join(rejected), "danger")
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


@bp.route("/project/<int:pid>/topology")
@login_required
def topology(pid):
    proj = _get_project_or_403(pid)
    files = proj.files
    devs = [f.device for f in files]
    topo = topo_mod.build_topology(devs) if devs else {"nodes": [], "links": []}
    return render_template("topology.html", p=proj, topo=topo)


@bp.route("/project/<int:pid>/summary")
@login_required
def summary_view(pid):
    proj = _get_project_or_403(pid)
    s = proj.summary
    md_html = None
    if proj.ai_enhanced and s.get("ai_markdown"):
        from .markdown_mini import md_to_html

        md_html = md_to_html(s["ai_markdown"])
    return render_template("summary.html", p=proj, s=s, md_html=md_html)


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
    md = to_markdown(proj.summary)
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
    s = proj.summary
    md = s.get("ai_markdown") or to_markdown(s)
    import io

    return send_file(io.BytesIO(md.encode("utf-8")), as_attachment=True,
                     download_name=f"executive_summary_{pid}.md", mimetype="text/markdown")
