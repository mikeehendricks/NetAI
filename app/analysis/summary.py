"""Executive summary builder — turns analysis results into business-ready content."""
from .common import SEV_ORDER

# Business-impact language per severity
_IMPACT = {
    "critical": "Direct path to compromise or outage; exploitable immediately.",
    "high": "Significant security or reliability exposure requiring prompt action.",
    "medium": "Weakens defences or operations; should be scheduled this quarter.",
    "low": "Hardening improvement with modest risk reduction.",
    "info": "Observation for completeness.",
}

_PHASE = {"critical": "Phase 1 - Immediate (0-7 days)", "high": "Phase 2 - Short term (7-30 days)",
          "medium": "Phase 3 - Planned (30-90 days)", "low": "Phase 4 - Backlog (next maintenance)",
          "info": "Phase 5 - Observations"}


def build(summary_doc_text, devices, findings, score, grade):
    by_sev = {s: 0 for s in SEV_ORDER}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    # per-device rollup
    devices_rollup = []
    for d in devices:
        fnd = [f for f in findings if f.get("device") == (d.get("hostname") or d.get("name"))]
        cnt = {s: 0 for s in SEV_ORDER}
        for f in fnd:
            cnt[f["severity"]] += 1
        d_score = sum(by_sev_w for by_sev_w in
                      [({"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}[s]) * cnt[s] for s in SEV_ORDER])
        devices_rollup.append({
            "hostname": d.get("hostname") or d.get("name") or "device",
            "vendor": d.get("vendor", "unknown"),
            "kind": d.get("kind", ""),
            "interfaces": len(d.get("interfaces", [])),
            "vlans": len(d.get("vlans", [])),
            "routes": len(d.get("routes", [])),
            "score": min(100, d_score),
            "counts": cnt,
        })

    # prioritised remediation roadmap
    roadmap = {p: [] for p in set(_PHASE.values())}
    for f in sorted(findings, key=lambda x: SEV_ORDER.index(x["severity"])):
        roadmap[_PHASE[f["severity"]]].append({
            "device": f.get("device"), "rule": f["rule_id"], "title": f["title"],
            "severity": f["severity"], "auto_fixable": f.get("auto_fixable", False),
        })

    # top 5 risks (narrative)
    top = findings[:8]
    return {
        "headline": _headline(by_sev, score, grade),
        "score": score,
        "grade": grade,
        "counts": by_sev,
        "total_findings": len(findings),
        "devices": devices_rollup,
        "roadmap": roadmap,
        "top_risks": [
            {
                "title": f["title"], "device": f.get("device"), "severity": f["severity"],
                "impact": _IMPACT[f["severity"]], "recommendation": f["recommendation"] or f["description"][:240],
            } for f in top
        ],
        "inventory_doc": summary_doc_text[:120],
        "auto_fixable": sum(1 for f in findings if f.get("auto_fixable")),
    }


def _headline(by_sev, score, grade):
    crit, high = by_sev.get("critical", 0), by_sev.get("high", 0)
    if crit:
        return (f"Urgent attention required: {crit} critical finding(s) with direct compromise potential; "
                f"overall network risk score {score}/100 (grade {grade}).")
    if high:
        return (f"Elevated risk: {high} high-severity weakness(es) reduce the network's resilience; "
                f"overall risk score {score}/100 (grade {grade}).")
    if by_sev.get("medium"):
        return (f"Moderate risk posture: core controls appear present with {by_sev['medium']} improvement area(s); "
                f"risk score {score}/100 (grade {grade}).")
    return f"Good security posture: no critical or high findings; risk score {score}/100 (grade {grade})."


def to_markdown(s: dict) -> str:
    L = []
    L.append(f"# Network Improvement Recommendations - Executive Summary\n")
    L.append(f"**Scope:** {s['total_findings']} findings across {len(s['devices'])} device(s)  ")
    L.append(f"**Overall risk score:** {s['score']}/100 (grade {s['grade']})  ")
    L.append(f"**Auto-fixable findings:** {s['auto_fixable']}\n")
    L.append("## 1. Executive overview\n")
    L.append(s["headline"] + "\n")
    c = s["counts"]
    L.append(f"| Severity | Critical | High | Medium | Low | Info |\n|---|---|---|---|---|---|")
    L.append(f"| Count | {c.get('critical',0)} | {c.get('high',0)} | {c.get('medium',0)} | {c.get('low',0)} | {c.get('info',0)} |\n")
    L.append("## 2. Top risks and business impact\n")
    for i, t in enumerate(s["top_risks"], 1):
        L.append(f"**{i}. [{t['severity'].upper()}] {t['title']}** - device: {t['device']}")
        L.append(f"- Impact: {t['impact']}")
        L.append(f"- Recommendation: {t['recommendation']}\n")
    L.append("## 3. Device inventory & risk\n")
    L.append("| Device | Vendor | Role | Interfaces | VLANs | Routes | Risk |")
    L.append("|---|---|---|---|---|---|---|")
    for d in s["devices"]:
        L.append(f"| {d['hostname']} | {d['vendor']} | {d['kind']} | {d['interfaces']} | {d['vlans']} | {d['routes']} | {d['score']}/100 |")
    L.append("")
    L.append("## 4. Remediation roadmap\n")
    for phase, items in s["roadmap"].items():
        if not items:
            continue
        L.append(f"### {phase}")
        for it in items:
            fix = " (auto-fix available)" if it["auto_fixable"] else ""
            L.append(f"- [{it['severity'].upper()}] {it['rule']}: {it['title']} - {it['device']}{fix}")
        L.append("")
    L.append("## 5. Methodology\n")
    L.append("NetAI parses each configuration (Palo Alto PAN-OS, Cisco IOS/IOS-XE, Fortinet FortiGateOS, "
             "Aruba AOS-CX/ArubaOS) and evaluates it against hardening benchmarks derived from CIS, vendor "
             "hardening guides and NIST SP 800-53 control families. Findings are scored by severity "
             "(critical 25 / high 15 / medium 8 / low 3 points) into a 0-100 risk score; lower is better. "
             "Executive summary enhanced where configured with an LLM review layer.")
    return "\n".join(L)
