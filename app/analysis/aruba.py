"""Aruba (AOS-CX / AOS-S / ArubaOS controller) parser + security rule engine."""
import re

from .common import finding, ip_interface, lines_with_ctx


def parse(text: str) -> dict:
    d = {"vendor": "aruba", "hostname": "", "model": "", "version": "",
         "interfaces": [], "vlans": [], "routes": [], "flags": {}, "raw": text}
    cur_if = None
    cur_vlan = None
    low_all = text.lower()

    m = re.search(r"^hostname\s+(\S+)", text, re.M | re.I)
    if m:
        d["hostname"] = m.group(1)
    m = re.search(r"(aruba\s+os|arubaos|aos-cx|procurve)", low_all)
    if m:
        d["model"] = m.group(1)

    for i, s, raw in lines_with_ctx(text):
        st = s.strip()
        indent = len(s) - len(s.lstrip())
        low = st.lower()

        if indent == 0 or True:  # aruba interfaces also match unindented in some dialects
            m = re.match(r"interface (?:\d+/\d+/)?(\d+(?:/\d+)*)$", st, re.I)
            if m and not low.startswith("interface vlan"):
                cur_if = {"name": st.split()[1], "ip": None, "prefix": None, "description": "",
                          "vlan_access": None, "trunk_vlans": [], "shutdown": False, "mode": "access"}
                d["interfaces"].append(cur_if)
                continue
            m = re.match(r"interface vlan (\d+)$", st, re.I)
            if m:
                cur_if = {"name": f"vlan{m.group(1)}", "ip": None, "prefix": None, "description": "",
                          "vlan_access": int(m.group(1)), "trunk_vlans": [], "shutdown": False, "mode": "svi"}
                d["interfaces"].append(cur_if)
                cur_vlan = int(m.group(1))
                continue
            m = re.match(r"^vlan (\d+)(?:\s+(\S.*))?$", st, re.I)
            if m:
                d["vlans"].append({"id": int(m.group(1)), "name": (m.group(2) or "").strip() if m.group(2) else ""})
                cur_if = None
                continue
            m = re.match(r"ip route (\S+) (\S+)(?: (\S+))?", st, re.I)
            if m:
                d["routes"].append({"dst": m.group(1), "nexthop": m.group(2) if len(m.groups()) < 3 or not m.group(3) else m.group(3)})
                cur_if = None
                continue
            if re.match(r"no (vlan|interface) ", low):
                cur_if = None
                continue
            for flag in ("web-management ssl", "no web-management", "web-management",
                         "telnet-server", "no telnet-server", "ip ssh", "no ip ssh",
                         "snmp-server community", "snmpv3", "mgmt-user", "aaa authentication login",
                         "aaa authorization", "ip authorized-managers", "ntp", "logging ",
                         "password manager", "user admin", "aruba-central", "sntp"):
                if low.startswith(flag):
                    d["flags"].setdefault(flag, []).append(st)
            if cur_if is not None:
                m = re.match(r"ip address (\S+)", st, re.I)
                if m and "/" in m.group(1):
                    itf = ip_interface(m.group(1))
                    if itf:
                        cur_if["ip"], cur_if["prefix"] = str(itf.ip), itf.network.prefixlen
                    continue
                m = re.match(r"ip address (\S+) (\S+)", st, re.I)
                if m:
                    itf = ip_interface(m.group(1), m.group(2))
                    if itf:
                        cur_if["ip"], cur_if["prefix"] = str(itf.ip), itf.network.prefixlen
                    continue
                m = re.match(r"description (.+)", st, re.I)
                if m:
                    cur_if["description"] = m.group(1)[:120]
                    continue
                m = re.match(r"vlan access (\d+)", st, re.I)
                if m:
                    cur_if["vlan_access"] = int(m.group(1))
                    continue
                m = re.match(r"vlan trunk allowed (\S+)", st, re.I)
                if m:
                    cur_if["trunk_vlans"] = m.group(1)
                    cur_if["mode"] = "trunk"
                    continue
                m = re.match(r"untagged vlan (\d+)", st, re.I)
                if m:
                    cur_if["vlan_access"] = int(m.group(1))
                    continue
                m = re.match(r"tagged vlan (\S+)", st, re.I)
                if m:
                    cur_if["trunk_vlans"] = m.group(1)
                    cur_if["mode"] = "trunk"
                    continue
                if re.match(r"(shutdown|disable)$", st, re.I):
                    cur_if["shutdown"] = True
                    continue
    return d


def analyze(parsed: dict):
    hostname = parsed.get("hostname") or "aruba-device"
    F = []
    flags = parsed.get("flags", {})
    joined = "\n".join(f for v in flags.values() for f in v)

    http_on = ("no web-management" not in joined) and bool(flags.get("web-management")) or \
              any(f.lower().startswith("web-management") and "ssl" not in f.lower() and not f.lower().startswith("web-management ssl")
                  for f in flags.get("web-management", []))
    has_http_disable = re.search(r"^no web-management\s*$", joined, re.M)
    if not has_http_disable and ("web-management" in flags or parsed.get("model")):
        F.append(finding("ARU-001", "high", "HTTP web management not explicitly disabled",
            "The HTTP management UI transmits admin credentials in cleartext and enlarges the attack surface.",
            evidence=flags.get("web-management", [])[:3],
            recommendation="Disable HTTP, keep HTTPS-only management.",
            remediation="no web-management\nweb-management ssl",
            auto_fixable=True, device=hostname))

    if flags.get("telnet-server") and not flags.get("no telnet-server"):
        F.append(finding("ARU-002", "high", "Telnet server enabled",
            "Telnet exposes the CLI and credentials in cleartext.",
            evidence=flags.get("telnet-server", [])[:2],
            recommendation="Disable telnet; use SSH.",
            remediation="no telnet-server\nip ssh version 2",
            auto_fixable=True, device=hostname))

    snmp = flags.get("snmp-server community", [])
    bad = [l for l in snmp if re.search(r"(public|private)", l, re.I)]
    if bad:
        F.append(finding("ARU-003", "high", "Default SNMP communities in use",
            "'public'/'private' communities let anyone enumerate (and on some platforms reconfigure) the device.",
            evidence=bad[:3],
            recommendation="Remove default communities and deploy SNMPv3 with auth+priv.",
            remediation=("no " + bad[0].split()[2] if len(bad[0].split()) > 2 else "") +
                        "\n! via CLI: no snmp-server community <name>\n"
                        "snmpv3 user netops auth sha <AUTH-PW> priv aes128 <PRIV-PW>",
            auto_fixable=False, device=hostname))

    # default/weak mgmt credentials
    weak_mgmt = [l for l in (flags.get("mgmt-user", []) + flags.get("password manager", []) + flags.get("user admin", []))
                 if re.search(r"(admin|manager|aruba|password|1234|cisco)", l, re.I) or len(l.split()) < 3]
    if weak_mgmt or "mgmt-user" in flags:
        F.append(finding("ARU-004", "critical", "Weak/default management credentials configured",
            "Default or weak admin passwords are the first thing automated attacks try; they must be replaced with strong unique credentials.",
            evidence=weak_mgmt[:3] or flags.get("mgmt-user", [])[:3],
            recommendation="Rotate management credentials to a 12+ character unique secret; prefer TACACS+/RADIUS for user auth.",
            remediation="! AOS-CX: password manager user-name admin plaintext <NEW-PASSWORD>\n"
                        "! ArubaOS: mgmt-user admin <NEW-PASSWORD>",
            auto_fixable=False, device=hostname))

    if re.search(r"^ip ssh (?!version 2)", joined, re.M) and "ip ssh version 2" not in joined:
        F.append(finding("ARU-005", "medium", "SSH version not pinned to 2",
            "Legacy SSH versions may still be negotiated.",
            recommendation="Force SSHv2 and strong ciphers.",
            remediation="ip ssh version 2\nip ssh cipher high\nip ssh kex curve-details nistp384",
            auto_fixable=True, device=hostname))

    if not flags.get("aaa authentication login") and not flags.get("aaa authorization"):
        F.append(finding("ARU-006", "medium", "No centralised AAA",
            "Device administration relies only on local accounts; no central control or audit trail.",
            recommendation="Integrate RADIUS/TACACS+ for admin authentication with local fallback.",
            remediation="aaa authentication login default radius local\n"
                        "aaa server group radius server 10.99.0.10 vrf default\n"
                        "radius-server host 10.99.0.10 key plaintext <KEY>",
            auto_fixable=True, device=hostname))

    if not flags.get("ntp") and not flags.get("sntp"):
        F.append(finding("ARU-007", "medium", "No NTP/SNTP configured",
            "Clock drift breaks log correlation and certificate validation.",
            remediation="ntp server 10.99.0.5\nntp server 10.99.0.6 prefer  ! (AOS-CX)\nntp enable",
            auto_fixable=True, device=hostname))

    if not any(f.startswith("logging ") for f in flags):
        F.append(finding("ARU-008", "medium", "No central logging configured",
            "Events remain only on the device and are lost on reboot.",
            remediation="logging 10.99.0.30\nlogging severity info  ! (AOS-CX syntax)",
            auto_fixable=True, device=hostname))

    if not flags.get("ip authorized-managers"):
        F.append(finding("ARU-009", "high", "No management access restriction (authorized-managers)",
            "Management web/SSH is reachable from any routed subnet.",
            recommendation="Restrict management to admin subnets.",
            remediation="ip authorized-managers 10.99.0.0 255.255.255.0 access manager read-write\n"
                        "ip authorized-managers 10.99.1.0 255.255.255.0 access manager read-write",
            auto_fixable=True, device=hostname))
    return F


def improve(parsed, findings):
    raw = parsed["raw"]
    out = []
    drop_telnet = any(f["rule_id"] == "ARU-002" for f in findings)
    drop_http = any(f["rule_id"] == "ARU-001" for f in findings)
    for line in raw.splitlines():
        st = line.strip()
        low = st.lower()
        if drop_telnet and low.startswith("telnet-server"):
            out.append("! [NetAI] removed: " + st)
            continue
        if drop_http and re.match(r"^web-management(?! ssl)", st, re.I):
            out.append("no web-management   ! [NetAI] was: " + st)
            continue
        if re.match(r"^snmp-server community (public|private)\b", st, re.I):
            out.append("no " + st + "   ! [NetAI] default community removed")
            continue
        out.append(line)
    blob = "\n".join(out).rstrip() + "\n"
    handled = {"ARU-001", "ARU-002"}
    extra = [f["remediation"] for f in findings if f["auto_fixable"] and f["rule_id"] not in handled]
    if extra:
        blob += ("\n#================= NetAI remediation (review before applying) =================\n"
                 + "\n".join(extra) + "\n#=============================================================================\n")
    return blob
