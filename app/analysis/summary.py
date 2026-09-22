"""Executive summary builder — turns analysis results into business-ready content."""
from .common import SEV_ORDER

# Executive-friendly severity fallback (business language, no jargon)
_IMPACT = {
    "critical": "Critical gap: an attacker needs almost no skill or time to exploit this. Fix this week to avoid a breach or outage.",
    "high": "Serious weakness: materially raises the chance of a successful cyberattack. Fix within the month as a business priority.",
    "medium": "Weakens the company's defences and audit readiness. Schedule the fix this quarter.",
    "low": "Low-cost hardening improvement that steadily reduces risk. Bundle into normal maintenance.",
    "info": "Observation only - no immediate action required.",
}

# Rule-specific business impact, written for non-technical executives.
_RULE_IMPACT = {
    # ---------------- Cisco
    "CIS-001": "Anyone who obtains a copy of this configuration file can recover the main device password in minutes and take full control of the device.",
    "CIS-002": "User passwords stored in the config can be reversed in seconds, handing attackers valid, trusted logins.",
    "CIS-003": "Admin sessions travel over the network unencrypted, so stolen credentials give attackers full control of the device.",
    "CIS-004": "Attackers from anywhere on the network can try to log in; one weak or reused password means full device takeover.",
    "CIS-005": "There is no central control of who can administer devices and no audit trail - a rogue or compromised account is hard to spot and hard to evict.",
    "CIS-006": "The device's unencrypted management web service exposes admin credentials to network eavesdroppers and has a long history of exploitable bugs.",
    "CIS-007": "Well-known default SNMP passwords let outsiders map the entire network - and with write access, change device settings.",
    "CIS-008": "The device can be talked into obsolete, breakable encryption, exposing management sessions to interception.",
    "CIS-009": "Weak encryption keys can be cracked, letting attackers read and hijack management sessions.",
    "CIS-010": "Automated password-guessing attacks can run indefinitely until they find valid credentials.",
    "CIS-011": "Forgotten admin sessions stay open indefinitely - anyone who reaches that keyboard acts as the admin.",
    "CIS-012": "Without a trusted clock, logs cannot be relied on in an investigation - attackers exploit that blind spot to hide their activity.",
    "CIS-013": "Security events are discarded - a break-in on this device could happen without leaving any evidence for investigators or auditors.",
    "CIS-014": "Obsolete services provide extra, unnecessary entry points and leak information about the device.",
    "CIS-015": "A rule that permits all traffic makes the surrounding firewall rules pointless - attackers can move freely between network zones once inside.",
    "CIS-016": "Without a legal warning banner, the company has a weaker position to prosecute intruders.",
    "CIS-017": "Passwords protected only by legacy obfuscation can be recovered from any lost or stolen config backup.",
    # ---------------- Palo Alto
    "PAN-001": "Every device can reach every other device on any port - one infected laptop can compromise the whole company in minutes (ransomware's favourite path).",
    "PAN-002": "The firewall cannot recognise or block malicious applications - command-and-control traffic passes through disguised as ordinary web browsing.",
    "PAN-003": "Allowed traffic is not recorded - the company could not investigate an incident on this rule or prove regulatory compliance.",
    "PAN-004": "The firewall's admin panel is reachable from anywhere; automated internet-wide scans will find it and continuously attempt to break in. This is the most common cause of firewall takeovers.",
    "PAN-005": "Administrator accounts can be brute-forced without ever being locked out, until a password falls.",
    "PAN-006": "Unreliable clocks undermine breach investigations and can break security certificates.",
    "PAN-007": "Admin credentials cross the network unencrypted and can be captured by anyone positioned to sniff traffic.",
    "PAN-008": "Old-format password hashes can be cracked offline from any copied configuration.",
    "PAN-009": "Obsolete TLS versions allow attackers to intercept traffic that users believe is protected.",
    "PAN-010": "The uploaded export contains no firewall policy, so traffic controls could not be verified in this review.",
    # ---------------- Fortinet
    "FGT-001": "The firewall's admin login accepts connections from the entire internet; automated attack campaigns try constantly and this is the number-one cause of firewall takeovers.",
    "FGT-002": "Admin logins can be sent unencrypted and captured on the network.",
    "FGT-003": "The first admin login attempt can be downgraded to an unencrypted page, exposing credentials.",
    "FGT-004": "Management channels may negotiate weak, breakable encryption.",
    "FGT-005": "Legacy TLS on the admin interface enables skilled attackers to intercept sessions.",
    "FGT-006": "The admin panel accepts unencrypted logins - credentials are exposed to network eavesdropping.",
    "FGT-007": "The main firewall rule lets every device reach everything - malware spreads freely between departments and nothing is contained.",
    "FGT-008": "Traffic through this rule is invisible to investigators and auditors - incidents on it can neither be detected nor reconstructed.",
    "FGT-009": "Allowed traffic is never inspected for malware - the firewall passes threats through as plain packets.",
    "FGT-010": "Attackers can keep guessing admin passwords without ever being blocked.",
    "FGT-011": "Long-idle admin sessions can be hijacked by anyone who reaches the console.",
    "FGT-012": "The default SNMP password lets outsiders inventory the network and plan attacks.",
    "FGT-013": "Out-of-sync clocks weaken breach investigations and certificate validation.",
    # ---------------- Aruba
    "ARU-001": "Switch admin credentials can be stolen in transit on the network.",
    "ARU-002": "Anyone sniffing the network can capture switch admin passwords in clear text.",
    "ARU-003": "Well-known default SNMP passwords expose device and network details to attackers.",
    "ARU-004": "Weak or factory-default admin passwords are the first thing automated attacks try - and they succeed.",
    "ARU-005": "Downgrade attacks can expose management sessions to interception.",
    "ARU-006": "There is no central control or audit trail of who administered this device.",
    "ARU-007": "Clock drift weakens investigations and breaks certificate validation.",
    "ARU-008": "Device events are not kept centrally - a breach on this device would go unseen.",
    "ARU-009": "The management interface is reachable from any network segment, multiplying the attack surface.",
    # ---------------- system
    "SYS-UNK": "The file could not be identified, so no security checks ran on it - risks in it are unknown and unmanaged.",
    "SYS-ERR": "The automated review hit an error on this file, so its risks may be understated.",
}

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
