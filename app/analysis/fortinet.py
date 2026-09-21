"""Fortinet FortiGate parser + security rule engine."""
import re

from .common import finding, lines_with_ctx


def parse(text: str) -> dict:
    d = {"vendor": "fortinet", "hostname": "", "model": "", "version": "",
         "interfaces": [], "vlans": [], "routes": [], "flags": {}, "policies": [], "raw": text}
    stack = []          # open 'config X' sections
    cur_edit = None     # open 'edit Y' name
    items = {}          # key/values of the current edit (or section-level sets)

    for i, s, raw in lines_with_ctx(text):
        st = s.strip()
        if st.startswith("config "):
            stack.append(st[7:].strip())
            cur_edit = None
            items = {}
            continue
        if st.startswith("edit "):
            cur_edit = st[5:].strip().strip('"')
            items = {}
            continue
        if st == "next":
            if cur_edit and stack:
                _collect(d, stack[-1], cur_edit, items)
            cur_edit = None
            items = {}
            continue
        if st == "end":
            if cur_edit and stack:          # some configs omit 'next'
                _collect(d, stack[-1], cur_edit, items)
            cur_edit = None
            items = {}
            if stack:
                stack.pop()
            continue
        m = re.match(r"set (\S+) (.*)", st)
        if m and stack:
            if cur_edit:
                items[m.group(1)] = m.group(2).strip().strip('"')
            else:
                _collect_global(d, stack[-1], m.group(1), m.group(2).strip().strip('"'))
            continue
        m = re.match(r"unset (\S+)", st)
        if m and stack and cur_edit:
            items[m.group(1)] = ""
            continue
    m = re.search(r"config-version=([^\s,]+)", text)
    if m:
        d["model"] = m.group(1)[:60]
    return d


def _collect_global(d, sect, key, val):
    if sect == "system global":
        if key == "hostname":
            d["hostname"] = val
        d["flags"].setdefault("global", {})[key] = val


def _collect(d, sect, edit, items):
    if sect == "system interface":
        ip = items.get("ip", "")
        mode = items.get("mode", "")
        if ip:
            ip_part, _, pl = ip.partition("/")
            d["interfaces"].append({
                "name": edit, "ip": ip_part, "prefix": int(pl) if pl.isdigit() else None,
                "description": items.get("description", ""), "vlan_access": items.get("vlanid"),
                "trunk_vlans": [], "shutdown": items.get("status") == "down",
                "mode": "vlan" if items.get("vlanid") else ("static" if mode != "dhcp" else "dhcp"),
                "allowaccess": items.get("allowaccess", ""),
            })
        else:
            d["interfaces"].append({"name": edit, "ip": None, "prefix": None,
                                    "description": items.get("description", ""), "vlan_access": None,
                                    "trunk_vlans": [], "shutdown": items.get("status") == "down",
                                    "mode": mode or "", "allowaccess": items.get("allowaccess", "")})
    elif sect == "router static":
        d["routes"].append({"dst": items.get("dst", ""), "nexthop": items.get("gateway", ""),
                            "iface": items.get("device", ""), "priority": items.get("priority", "")})
    elif sect == "system admin":
        d["flags"].setdefault("admins", {})[edit] = items
    elif sect == "system snmp community":
        d["flags"].setdefault("snmp", []).append({"name": edit, **items})
    elif sect == "firewall policy":
        d["policies"].append({"id": edit, "name": items.get("name", ""), **items})


def analyze(parsed: dict):
    hostname = parsed.get("hostname") or "fortigate"
    F = []
    flags = parsed.get("flags", {})
    g = flags.get("global", {})

    # admin access restrictions
    for admin, items in (flags.get("admins") or {}).items():
        for k in ("trusthost1", "trusthost2", "trusthost3"):
            th = items.get(k, "")
            if th.startswith("0.0.0.0"):  # nosec B104 - parsing config data
                F.append(finding("FGT-001", "critical",
                    f"Admin account '{admin}' is open to any source (trusthost 0.0.0.0/0)",
                    "The admin GUI/API of this firewall accepts logins from the entire internet if the port is reachable. "
                    "This is the most common FortiGate compromise path (CVE-linked brute campaigns scan 443/22 continuously).",
                    evidence=[f"config system admin / edit {admin} / set {k} {th}"],
                    recommendation="Restrict every admin trusthost to management subnets; create dedicated admin hosts object.",
                    remediation=("config system admin\n" + f"    edit \"{admin}\"\n"
                                 "        set trusthost1 10.99.0.0 255.255.255.0\n"
                                 "        set trusthost2 <VPN-SUBNET> <MASK>\n    next\nend"),
                    auto_fixable=True, device=hostname))

    # http admin access
    aa_bad = [i for i in parsed["interfaces"] if "http" in (i.get("allowaccess") or "").lower()]
    if aa_bad:
        F.append(finding("FGT-002", "high", "HTTP admin access enabled on interfaces",
            "Cleartext HTTP login leaks credentials; HTTPS redirect alone is not enough when http is permitted.",
            evidence=[f"{i['name']}: allowaccess={i['allowaccess']}" for i in aa_bad[:4]],
            recommendation="Remove http (and telnet/snmp if unused) from allowaccess; keep https+ssh.",
            remediation="\n".join(f"config system interface\n    edit \"{i['name']}\"\n"
                                  f"        set allowaccess {('https ssh' if 'ssh' in i['allowaccess'].lower() else 'https')}\n"
                                  "    next\nend" for i in aa_bad[:3]),
            auto_fixable=True, device=hostname))

    # https redirect / strong crypto
    if g.get("admin-https-redirect") != "enable":
        F.append(finding("FGT-003", "medium", "admin-https-redirect not enforced",
            "GUI requests are not force-redirected to TLS, allowing first-visit credential exposure.",
            remediation="config system global\n    set admin-https-redirect enable\nend",
            auto_fixable=True, device=hostname))
    if g.get("strong-crypto") != "enable":
        F.append(finding("FGT-004", "medium", "strong-crypto disabled",
            "Without strong-crypto, admin and HA/backup channels may negotiate legacy ciphers.",
            remediation="config system global\n    set strong-crypto enable\nend",
            auto_fixable=True, device=hostname))
    for tlsv in ("admin-TLSv1", "admin-TLSv1-1"):
        if g.get(tlsv) == "enable":
            F.append(finding("FGT-005", "medium", f"{tlsv} enabled",
                "Legacy TLS permitted on the admin GUI enables downgrade attacks.",
                remediation=f"config system global\n    set {tlsv} disable\nend",
                auto_fixable=True, device=hostname))
    if g.get("admin-sport", "443") == "80":
        F.append(finding("FGT-006", "high", "Admin GUI on cleartext port 80",
            "Management traffic is unencrypted.", remediation="config system global\n    set admin-sport 443\nend",
            auto_fixable=True, device=hostname))

    # policies
    for p in parsed.get("policies", []):
        action = p.get("action", "accept")
        src = (p.get("srcaddr", "") or "").strip('"')
        dst = (p.get("dstaddr", "") or "").strip('"')
        svc = (p.get("service", "") or "").strip('"')
        logt = p.get("logtraffic", "")
        if action == "accept" and src in ("all", "") and dst in ("all", "") and svc.upper() in ("ALL", ""):
            F.append(finding("FGT-007", "critical",
                f"Firewall policy {p['id']} ({p.get('name','')}) permits any-any-any",
                "A single any/any/any accept policy removes all segmentation and inspection control.",
                evidence=[f"policy id={p['id']} srcintf={p.get('srcintf')} dstintf={p.get('dstintf')} srcaddr={src} dstaddr={dst} service={svc}"],
                recommendation="Replace with explicit address objects and services per business flow.",
                remediation=(f"config firewall policy\n    edit {p['id']}\n"
                             "        set srcaddr <INTERNAL-SUBNETS>\n        set dstaddr <REMOTE-SUBNETS>\n"
                             "        set service <REQUIRED-SERVICES>\n    next\nend"),
                auto_fixable=False, device=hostname))
        if action == "accept" and logt not in ("all", "utm"):
            F.append(finding("FGT-008", "high",
                f"Firewall policy {p['id']} ({p.get('name','')}) does not log allowed traffic",
                "No logs for accepted flows = zero visibility for incident response and audits.",
                evidence=[f"policy id={p['id']} logtraffic={logt or 'unset'}"],
                recommendation="Enable 'set logtraffic all' (or utm) and bind a log profile.",
                remediation=f"config firewall policy\n    edit {p['id']}\n        set logtraffic all\n    next\nend",
                auto_fixable=True, device=hostname))
        if action == "accept" and not p.get("av-profile") and not p.get("ips-sensor") and svc.upper() != "PING":
            F.append(finding("FGT-009", "medium",
                f"Policy {p['id']} ({p.get('name','')}) has no security profiles",
                "Allowed flows are not inspected by antivirus/IPS/web-filter - the firewall works as a pure packet filter.",
                recommendation="Attach a UTM profile set (IPS at minimum) to inter-zone accept policies.",
                remediation=(f"config firewall policy\n    edit {p['id']}\n        set ips-sensor <default-ips>\n"
                             "        set av-profile <default-av>\n    next\nend"),
                auto_fixable=False, device=hostname))

    # admin lockout
    if not g.get("admin-lockout-threshold"):
        F.append(finding("FGT-010", "medium", "Admin lockout not configured",
            "Unlimited admin password guessing is possible.",
            remediation="config system admin\n    set admin-lockout-threshold 5\n    set admin-lockout-duration 900\nend",
            auto_fixable=True, device=hostname))
    # admintimeout
    try:
        to = int(g.get("admintimeout", "5"))
    except ValueError:
        to = 5
    if to > 15:
        F.append(finding("FGT-011", "low", f"Admin idle timeout is high ({to} min)",
            "Long-lived idle admin sessions increase hijack risk.",
            remediation="config system global\n    set admintimeout 10\nend",
            auto_fixable=True, device=hostname))
    # snmp
    for c in flags.get("snmp", []):
        if str(c.get("name", "")).lower() in ("public", "private"):
            F.append(finding("FGT-012", "high", f"Default SNMP community '{c.get('name')}' present",
                "Default communities allow device enumeration/fingerprinting.",
                remediation="config system snmp community\n    edit " + str(c.get("id", "0")) + "\n        unset name\n    next\nend  ! (or rename+restrict with 'set hosts')",
                auto_fixable=False, device=hostname))
    if not g.get("ntpserver") and not g.get("ntpsync") == "enable":
        F.append(finding("FGT-013", "medium", "NTP not synchronised (system global)",
            "Time skew breaks log correlation and certificate validation.",
            remediation="config system global\n    set ntpsync enable\n    set ntpserver \"10.99.0.5\"\nend",
            auto_fixable=True, device=hostname))
    return F


def improve(parsed, findings):
    raw = parsed["raw"]
    out = []
    for line in raw.splitlines():
        st = line.strip()
        # remove http from allowaccess lines
        m = re.match(r"set allowaccess (.+)", st)
        if m and re.search(r"\bhttp\b(?!s)", m.group(1)):
            new = re.sub(r"\bhttp\b(?!s)", "", m.group(1)).split()
            new = [t for t in new if t]
            indent = line[: len(line) - len(line.lstrip())]
            out.append(indent + "set allowaccess " + " ".join(new or ["https"]) + "   ! [NetAI] was: " + st)
            continue
        out.append(line)
    blob = "\n".join(out).rstrip() + "\n"
    extra = [f["remediation"] for f in findings if f["auto_fixable"]]
    if extra:
        blob += ("\n#================= NetAI remediation (review before applying) =================\n"
                 + "\n\n".join(extra) + "\n#=============================================================================\n")
    return blob
