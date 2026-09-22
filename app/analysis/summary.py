"""Executive summary builder — turns analysis results into business-ready content."""
from .common import SEV_ORDER

# Executive-friendly severity fallback (business language, no jargon)
_IMPACT = {
    "critical": "Critical: an attacker needs almost no skill or time to exploit this. Expect data breach, service outage, or both - remediate this week.",
    "high": "High: materially raises the likelihood of a successful cyberattack on the business. Remediate within 30 days.",
    "medium": "Medium: erodes the company's defences and its audit readiness (ISO 27001 / SOC 2 / PCI evidence). Schedule the fix this quarter.",
    "low": "Low: inexpensive hardening that steadily reduces risk. Bundle into normal maintenance.",
    "info": "Informational: no immediate action required; noted for completeness.",
}

# Rule-specific business impact, written for C-level readers: each entry leads
# with the business consequence (money, customers, uptime, compliance,
# reputation) rather than the technical mechanism.
_RULE_IMPACT = {
    # ---------------- Cisco
    "CIS-001": "A leaked or stolen copy of this configuration hands attackers the device's master admin password within minutes - full control, able to intercept traffic or cause an outage. Config backups must be protected like customer data.",
    "CIS-002": "Every account password on this device can be decoded in seconds from any config backup - attackers get legitimate logins, and investigators can no longer tell attacker activity from staff activity.",
    "CIS-003": "Administrators sign in without encryption, so their credentials can be stolen straight off the network. One captured login equals full control of the device.",
    "CIS-004": "Anyone on the network - including one malware-infected laptop - can attempt to break into this device, and nothing stops the guessing until a password falls.",
    "CIS-005": "There is no central control of who can administer devices and no record of what they did. After an incident the company cannot answer 'who did what?' - auditors treat this as a serious control failure.",
    "CIS-006": "The device's unencrypted web management exposes admin passwords to network eavesdroppers and carries a history of bugs that allow takeover without any password.",
    "CIS-007": "Industry-default monitoring credentials let outsiders inventory the entire network - and potentially change device settings - without logging in.",
    "CIS-008": "Management sessions can be negotiated down to breakable encryption, exposing the very traffic - credentials, configurations, customer data - the business believes is protected.",
    "CIS-009": "The device's encryption keys are weak enough to be cracked, letting attackers read and hijack administrative sessions.",
    "CIS-010": "Automated password-guessing can run around the clock without being blocked - persistence eventually beats any weak password.",
    "CIS-011": "Abandoned admin sessions never time out - anyone who reaches an unattended terminal inherits full admin rights to the network.",
    "CIS-012": "Without a trusted clock the device's logs cannot be relied on in an investigation - delays and blind spots that raise the cost of every incident.",
    "CIS-013": "Security events are thrown away. A break-in on this device could leave no evidence at all - uninvestigable, and a compliance failure in its own right.",
    "CIS-014": "Unused legacy services give attackers free information about the device and extra ways in - pure downside, no business benefit.",
    "CIS-015": "A 'permit all' rule defeats the network zoning that contains incidents: once inside, attackers can reach systems anywhere - the pattern regulators expect companies to prevent.",
    "CIS-016": "Without a legal warning banner the company is in a weaker position to prosecute intruders - a small gap with real cost in court.",
    "CIS-017": "Legacy-obfuscated passwords can be recovered from any lost or leaked backup copy - every exported config becomes a liability.",
    # ---------------- Palo Alto
    "PAN-001": "One rule lets every device talk to everything. Malware that lands anywhere - a laptop, a supplier link - spreads unchecked; this is the pattern behind company-wide ransomware events.",
    "PAN-002": "The firewall passes traffic it cannot identify, so command-and-control and data theft blend into normal browsing - breaches can go undetected for months.",
    "PAN-003": "Traffic on this rule leaves no record: the company could neither investigate an incident on it nor evidence compliance to auditors or regulators.",
    "PAN-004": "The firewall's admin panel is visible to the entire internet and under constant automated attack - the single most common cause of full firewall takeover.",
    "PAN-005": "Administrator accounts can be brute-forced indefinitely without lockout - persistence beats weak passwords every time.",
    "PAN-006": "Unreliable device clocks undermine breach investigations and can break certificate validation - a small gap with outsized cost during an incident.",
    "PAN-007": "Admin credentials cross the network unencrypted and can be captured by anyone positioned to listen.",
    "PAN-008": "Old-format password hashes can be cracked offline from any copied configuration - a leaked backup becomes a breach.",
    "PAN-009": "Outdated encryption lets attackers read traffic that users believe is private - direct customer-data exposure risk.",
    "PAN-010": "The firewall's traffic rules could not be reviewed, so the highest-risk area of this device is unknown and unmanaged.",
    # ---------------- Fortinet
    "FGT-001": "The firewall's admin login accepts connections from the entire internet; automated campaigns attack it constantly. Exposed admin panels are the number-one cause of firewall takeovers.",
    "FGT-002": "Admin sign-ins can be sent unencrypted and captured off the network - one captured login equals full control.",
    "FGT-003": "The login page can be forced back to an unencrypted version, exposing credentials even where encryption is configured.",
    "FGT-004": "Management channels can negotiate weak, breakable encryption.",
    "FGT-005": "Outdated encryption on the admin interface lets skilled attackers intercept sessions.",
    "FGT-006": "The admin panel accepts unencrypted logins - credentials are exposed to network eavesdropping.",
    "FGT-007": "A single rule lets everything reach everything - malware moves freely between departments and nothing contains it; the pattern behind company-wide ransomware.",
    "FGT-008": "Traffic through this rule is invisible to investigators and auditors - incidents on it can neither be detected nor reconstructed.",
    "FGT-009": "Allowed traffic is never scanned for malware - threats ride through as ordinary packets.",
    "FGT-010": "Attackers can keep guessing admin passwords without ever being blocked.",
    "FGT-011": "Long-idle admin sessions can be hijacked by anyone who reaches the console.",
    "FGT-012": "The default monitoring password lets outsiders map the network and plan attacks.",
    "FGT-013": "Out-of-sync clocks weaken breach investigations and certificate validation.",
    # ---------------- Aruba
    "ARU-001": "Switch admin passwords can be captured in clear text off the network - one sniffed login compromises every switch administered the same way.",
    "ARU-002": "Anyone monitoring the network can read switch admin passwords in clear text.",
    "ARU-003": "Default monitoring credentials expose device and network details to attackers.",
    "ARU-004": "Factory-default or weak admin passwords are the first thing automated attacks try - and they succeed.",
    "ARU-005": "Downgrade attacks can strip encryption from management sessions.",
    "ARU-006": "No central record exists of who administered the device or what they changed. After an incident, 'who did what?' is unanswerable - auditors treat this as a serious control failure.",
    "ARU-007": "Clock drift weakens investigations and breaks certificate validation.",
    "ARU-008": "Device events are not kept centrally - a breach on this device would go unseen.",
    "ARU-009": "The management interface is reachable from any network segment - one compromised laptop is enough to reach it.",
    # ---------------- system
    "SYS-UNK": "This file could not be identified, so none of the security checks ran on it - its risks are unknown and unmanaged.",
    "SYS-ERR": "The automated review hit an error on this file, so its risks may be understated.",
}

# Bump when executive-summary generation changes so stored project summaries
# can be refreshed lazily (see main._fresh_summary).
SUMMARY_GEN = 2

_PHASE = {"critical": "Phase 1 - Immediate (0-7 days)", "high": "Phase 2 - Short term (7-30 days)",
          "medium": "Phase 3 - Planned (30-90 days)", "low": "Phase 4 - Backlog (next maintenance)",
          "info": "Phase 5 - Observations"}


def _impact_for(f):
    return _RULE_IMPACT.get(f.get("rule_id"), _IMPACT[f["severity"]])


def build(summary_doc_text, devices, findings, score, grade):
    by_sev = {s: 0 for s in SEV_ORDER}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    # per-device rollup
    devices_rollup = []
    sev_weight = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    for d in devices:
        fnd = [f for f in findings if f.get("device") == (d.get("hostname") or d.get("name"))]
        cnt = {s: 0 for s in SEV_ORDER}
        for f in fnd:
            cnt[f["severity"]] += 1
        d_score = sum(sev_weight[s] * cnt[s] for s in SEV_ORDER)
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

    # prioritised remediation roadmap (with concrete config fixes)
    roadmap = {p: [] for p in set(_PHASE.values())}
    for f in sorted(findings, key=lambda x: SEV_ORDER.index(x["severity"])):
        roadmap[_PHASE[f["severity"]]].append({
            "device": f.get("device"), "rule": f["rule_id"], "title": f["title"],
            "severity": f["severity"], "auto_fixable": f.get("auto_fixable", False),
            "rec": f.get("recommendation", ""),
            "config": f.get("remediation", ""),
            "impact": _impact_for(f),
        })

    top = findings[:8]
    return {
        "gen": SUMMARY_GEN,
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
                "impact": _impact_for(f),
                "recommendation": f["recommendation"] or f["description"][:240],
                "config": f.get("remediation", ""),
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
    L.append("# Network Improvement Recommendations - Executive Summary\n")
    L.append(f"**Scope:** {s['total_findings']} findings across {len(s['devices'])} device(s)  ")
    L.append(f"**Overall risk score:** {s['score']}/100 (grade {s['grade']})  ")
    L.append(f"**Auto-fixable findings:** {s['auto_fixable']}\n")
    L.append("## 1. Executive overview\n")
    L.append(s["headline"] + "\n")
    c = s["counts"]
    L.append("| Severity | Critical | High | Medium | Low | Info |")
    L.append("|---|---|---|---|---|---|")
    L.append(f"| Count | {c.get('critical',0)} | {c.get('high',0)} | {c.get('medium',0)} | {c.get('low',0)} | {c.get('info',0)} |\n")
    L.append("## 2. Top risks and business impact\n")
    for i, t in enumerate(s["top_risks"], 1):
        L.append(f"**{i}. [{t['severity'].upper()}] {t['title']}** - device: {t['device']}")
        L.append(f"- Business impact: {t['impact']}")
        L.append(f"- Recommendation: {t['recommendation']}")
        if t.get("config"):
            L.append("- Fix (config to apply):")
            L.append("```")
            L.append(t["config"])
            L.append("```\n")
    L.append("## 3. Device inventory & risk\n")
    L.append("| Device | Vendor | Role | Interfaces | VLANs | Routes | Risk |")
    L.append("|---|---|---|---|---|---|---|")
    for d in s["devices"]:
        L.append(f"| {d['hostname']} | {d['vendor']} | {d['kind']} | {d['interfaces']} | {d['vlans']} | {d['routes']} | {d['score']}/100 |")
    L.append("")
    L.append("## 4. Remediation roadmap (with config fixes)\n")
    for phase, items in s["roadmap"].items():
        if not items:
            continue
        L.append(f"### {phase}")
        for it in items:
            fix = " (auto-fix available)" if it["auto_fixable"] else ""
            L.append(f"- **[{it['severity'].upper()}] {it['rule']}: {it['title']}** - {it['device']}{fix}")
            if it.get("impact"):
                L.append(f"  - Impact: {it['impact']}")
            if it.get("config"):
                L.append("  - Config fix:")
                L.append("  ```")
                for ln in it["config"].splitlines():
                    L.append("  " + ln)
                L.append("  ```")
        L.append("")
    L.append("## 5. Methodology\n")
    L.append("NetAI parses each configuration (Palo Alto PAN-OS, Cisco IOS/IOS-XE, Fortinet FortiGateOS, "
             "Aruba AOS-CX/ArubaOS) and evaluates it against hardening benchmarks derived from CIS, vendor "
             "hardening guides and NIST SP 800-53 control families. Findings are scored by severity "
             "(critical 25 / high 15 / medium 8 / low 3 points) into a 0-100 risk score; lower is better. "
             "Executive summary enhanced where configured with an LLM review layer.")
    return "\n".join(L)
