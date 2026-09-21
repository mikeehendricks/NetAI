"""Palo Alto PAN-OS parser (XML export or 'set' format) + security rule engine."""
import re
import defusedxml.ElementTree as ET  # hardened parser for untrusted uploads

from .common import finding, lines_with_ctx


def _txt(node):
    return node.text.strip() if node is not None and node.text else ""


def _members(node):
    if node is None:
        return []
    if node.tag == "member":
        return [_txt(node)]
    return [_txt(m) for m in node.findall(".//member") if _txt(m)]


def parse(text: str) -> dict:
    d = {
        "vendor": "paloalto", "hostname": "", "model": "", "version": "",
        "interfaces": [], "vlans": [], "routes": [], "flags": {}, "rules": [], "raw": text,
    }
    st = text.lstrip()
    if st.startswith("<?xml") or st.startswith("<"):
        d.update(_parse_xml(text))
    else:
        d.update(_parse_set(text))
    return d


def _parse_xml(text):
    d = {"interfaces": [], "vlans": [], "routes": [], "flags": {}, "rules": []}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return d
    # device/system
    sysn = root.find(".//deviceconfig/system")
    if sysn is not None:
        d["hostname"] = _txt(sysn.find("hostname"))
        d["flags"]["permitted-ip"] = [_txt(m) for m in sysn.findall("permitted-ip/entry")]
        d["flags"]["admin-lockout"] = _txt(sysn.find("admin-lockout/failed-attempts"))
        d["flags"]["password-complexity"] = _txt(sysn.find("password-complexity/enabled"))
        if sysn.find("ntp-servers") is not None:
            d["flags"]["ntp"] = ["configured"]
    d["model"] = _txt(root.find(".//deviceconfig/system/hostname"))
    # interfaces
    for entry in root.findall(".//network/interface/ethernet/entry"):
        ifname = entry.get("name", "ethernet?")
        layer3 = entry.find("layer3")
        if layer3 is not None:
            for unit in layer3.findall("units/entry"):
                ipn = unit.find("ip/entry")
                d["interfaces"].append({
                    "name": f"{ifname}.{unit.get('name','1')}" if unit.get("name") not in (None, "1") else ifname,
                    "ip": _txt(ipn).split("/")[0] if ipn is not None else None,
                    "prefix": (lambda s: int(s.split("/")[1]) if "/" in s else None)(_txt(ipn)),
                    "description": _txt(unit.find("comment")),
                    "vlan_access": None, "trunk_vlans": [], "shutdown": False, "mode": "layer3",
                })
        if entry.find("layer2") is not None:
            d["interfaces"].append({"name": ifname, "ip": None, "prefix": None, "description": "",
                                    "vlan_access": None, "trunk_vlans": [], "shutdown": False, "mode": "layer2"})
    # virtual routers static routes
    for vr in root.findall(".//network/virtual-router/entry"):
        for rt in vr.findall("routing-table/ip/static-route/entry"):
            nh = _txt(rt.find("nexthop/ip-address"))
            dst = _txt(rt.find("destination")) or rt.get("name", "")
            d["routes"].append({"dst": dst, "nexthop": nh, "iface": _txt(rt.find("interface"))})
    # security rules
    for r in root.findall(".//vsys/entry/rulebase/security/rules/entry"):
        d["rules"].append({
            "name": r.get("name", ""),
            "from": _members(r.find("from")),
            "to": _members(r.find("to")),
            "source": _members(r.find("source")),
            "destination": _members(r.find("destination")),
            "service": _members(r.find("service")),
            "application": _members(r.find("application")),
            "action": _txt(r.find("action")),
            "log-end": _txt(r.find("log-end")) or "",
            "log-setting": _txt(r.find("log-setting")) or "",
            "profile-group": _txt(r.find("profile-setting/group")) or "",
        })
    # management profile services
    d["flags"]["mgmt-profiles"] = {}
    for mp in root.findall(".//network/profiles/interface-management/entry"):
        svcs = [t for t in ("http", "telnet", "ping", "ssh", "https") if mp.find(t) is not None]
        d["flags"]["mgmt-profiles"][mp.get("name", "")] = svcs
    # tls profiles
    d["flags"]["tls-min"] = {}
    for tls in root.findall(".//shared/ssl-tls-service-profile/entry") + root.findall(".//devices/entry//ssl-tls-service-profile/entry"):
        d["flags"]["tls-min"][tls.get("name", "")] = _txt(tls.find("protocol-settings/min-version"))
    return d


_SET_RULE = re.compile(r"^set rulebase security rules (\S+)")


def _parse_set(text):
    d = {"interfaces": [], "vlans": [], "routes": [], "flags": {}, "rules": {}}
    rules = {}
    routes_acc = {}
    for _, s, raw in lines_with_ctx(text):
        st = s.strip()
        m = re.match(r"set deviceconfig system hostname (\S+)", st)
        if m:
            d["hostname"] = m.group(1)
            continue
        m = re.match(r"set deviceconfig system ip-address (\S+)", st)
        if m:
            d["flags"]["mgmt-ip"] = m.group(1)
            continue
        m = re.match(r"set network interface ethernet (\S+) layer3 ip (\S+)", st)
        if m:
            ip = m.group(2)
            d["interfaces"].append({
                "name": m.group(1), "ip": ip.split("/")[0],
                "prefix": int(ip.split("/")[1]) if "/" in ip else None,
                "description": "", "vlan_access": None, "trunk_vlans": [], "shutdown": False,
                "mode": "layer3",
            })
            continue
        m = re.match(r"set network interface ethernet (\S+) layer3 units (\S+) ip (\S+)", st)
        if m:
            name = m.group(2) if m.group(2) not in ("1",) else m.group(1)
            ip = m.group(3)
            d["interfaces"].append({
                "name": name, "ip": ip.split("/")[0],
                "prefix": int(ip.split("/")[1]) if "/" in ip else None,
                "description": "", "vlan_access": None, "trunk_vlans": [], "shutdown": False,
                "mode": "layer3",
            })
            continue
        m = re.match(r"set network interface ethernet (\S+) comment (.+)", st)
        if m:
            for ifc in d["interfaces"]:
                if ifc["name"].startswith(m.group(1)) and not ifc["description"]:
                    ifc["description"] = m.group(2)[:120]
            continue
        m = re.match(r"set network interface ethernet (\S+) layer3 interface-management-profile (\S+)", st)
        if m:
            d["flags"].setdefault("iface-mgmt-profile", []).append((m.group(1), m.group(2)))
            continue
        m = re.match(r"set network virtual-router (\S+) routing-table ip static-route (\S+) (.+)", st)
        if m:
            rname, rest = m.group(2), m.group(3)
            e = routes_acc.setdefault(rname, {"dst": "", "nexthop": "", "iface": ""})
            m2 = re.match(r"nexthop ip-address (\S+)", rest)
            if m2:
                e["nexthop"] = m2.group(1)
            m2 = re.match(r"destination (\S+)", rest)
            if m2:
                e["dst"] = m2.group(1)
            m2 = re.match(r"interface (\S+)", rest)
            if m2:
                e["iface"] = m2.group(1)
            continue
        m = _SET_RULE.match(st)
        if m:
            rname = m.group(1)
            r = rules.setdefault(rname, {
                "name": rname, "from": [], "to": [], "source": [], "destination": [],
                "service": [], "application": [], "action": "", "log-end": "",
                "log-setting": "", "profile-group": "",
            })
            m2 = re.match(r"set rulebase security rules \S+ (\S+) (.+)", st)
            if m2:
                key, val = m2.group(1), m2.group(2).strip()
                if val.startswith("["):
                    val = val.strip("[]").split()
                else:
                    val = [val]
                if key in ("from", "to", "source", "destination", "service", "application"):
                    r[key].extend(val)
                elif key == "action":
                    r["action"] = val[0]
                elif key == "log-end":
                    r["log-end"] = val[0]
                elif key == "log-setting":
                    r["log-setting"] = val[0]
                elif key == "profile-setting":
                    if len(val) > 1 and val[0] == "group":
                        r["profile-group"] = val[1]
            continue
        m = re.match(r"set deviceconfig system permitted-ip (.+)", st)
        if m:
            d["flags"].setdefault("permitted-ip", []).append(m.group(1).strip("[]"))
    d["rules"] = list(rules.values())
    d["routes"] = list(routes_acc.values())
    return d


# --------------------------------------------------------------------- rules
def analyze(parsed: dict):
    hostname = parsed.get("hostname") or "paloalto-fw"
    F = []
    flags = parsed.get("flags", {})

    # any-any allow rules
    for r in parsed.get("rules", []):
        if r.get("action") != "deny" and r.get("action") != "drop":
            any_src = not r["source"] or "any" in r["source"]
            any_dst = not r["destination"] or "any" in r["destination"]
            any_svc = not r["service"] or "any" in r["service"]
            any_app = not r["application"] or "any" in r["application"]
            if any_src and any_dst and any_svc:
                F.append(finding("PAN-001", "critical",
                    f"Security rule '{r['name']}' allows ANY-ANY traffic",
                    "A rule with source=any, destination=any, service=any defeats zone segmentation: "
                    "any host can reach any host on any port, including east-west lateral movement.",
                    evidence=[f"rule: {r['name']}  src={r['source']} dst={r['destination']} svc={r['service']} app={r['application']}"],
                    recommendation="Split the rule into explicit application/service entries with named address objects.",
                    remediation=("set rulebase security rules " + r['name'] + " service service-http\n"
                                 "! Better: create app-specific rules and remove the any/any/any rule:\n"
                                 "set rulebase security rules web-out from [ " + " ".join(r['from'] or ['any']) + " ] to [ "
                                 + " ".join(r['to'] or ['any']) + " ] source [ <trusted-subnet> ] destination [ any ] "
                                 "service [ service-http service-https ] application [ web-browsing ssl ] action allow"),
                    auto_fixable=False, device=hostname))
            elif any_svc and any_app:
                F.append(finding("PAN-002", "high",
                    f"Rule '{r['name']}' allows any application on any port",
                    "App-Id cannot enforce control when application=any; evasive apps and C2 tunnels pass freely.",
                    evidence=[f"rule: {r['name']} svc={r['service']} app={r['application']}"],
                    recommendation="Enumerate required applications per rule; keep an explicit any rule only at the bottom, action deny.",
                    remediation=f"set rulebase security rules {r['name']} application [ web-browsing ssl dns ]",
                    auto_fixable=False, device=hostname))
            if r.get("action") == "allow" and (r.get("log-end") in ("", "no") and not r.get("log-setting")):
                F.append(finding("PAN-003", "high",
                    f"Allow rule '{r['name']}' has no session logging",
                    "Without logging you have no visibility into allowed traffic - incidents cannot be investigated.",
                    evidence=[f"rule: {r['name']} log-end={r.get('log-end') or 'unset'}"],
                    recommendation="Enable log at session end and bind a log-forwarding profile.",
                    remediation=(f"set rulebase security rules {r['name']} log-end yes log-setting <log-profile>"),
                    auto_fixable=True, device=hostname))

    # management plane
    if not flags.get("permitted-ip"):
        F.append(finding("PAN-004", "critical",
            "Management interface has no permitted-IP restriction",
            "The management web/API/SSH surface is reachable from any network. Internet-exposed management panels are the #1 firewall compromise vector.",
            recommendation="Lock management access to admin subnets only.",
            remediation="set deviceconfig system permitted-ip 10.99.0.0/24\nset deviceconfig system permitted-ip <VPN-SUBNET>",
            auto_fixable=True, device=hostname))
    if not flags.get("admin-lockout"):
        F.append(finding("PAN-005", "medium", "No administrator lockout configured",
            "Admin accounts can be brute-forced indefinitely.",
            recommendation="Enable lockout after 5 failures for 30 minutes plus password complexity.",
            remediation="set deviceconfig system admin-lockout failed-attempts 5\n"
                        "set deviceconfig system admin-lockout lockout-duration 30\n"
                        "set deviceconfig system password-complexity enabled yes minimum-length 12",
            auto_fixable=True, device=hostname))
    if not flags.get("ntp"):
        F.append(finding("PAN-006", "medium", "Device has no NTP servers",
            "Logs without trusted time undermine forensic value and break Kerberos/TLS validation.",
            recommendation="Configure primary/secondary NTP.",
            remediation="set deviceconfig system ntp-servers primary-ntp-server address 10.99.0.5\n"
                        "set deviceconfig system ntp-servers secondary-ntp-server address 10.99.0.6",
            auto_fixable=True, device=hostname))

    # management profiles exposing weak services
    for pname, svcs in (flags.get("mgmt-profiles") or {}).items():
        weak = [s for s in svcs if s in ("http", "telnet")]
        if weak:
            F.append(finding("PAN-007", "high",
                f"Interface management profile '{pname}' permits cleartext services ({', '.join(weak)})",
                "HTTP/Telnet on any interface transmits credentials in cleartext.",
                evidence=[f"{pname}: {svcs}"],
                recommendation="Remove http/telnet; keep https+ssh only.",
                remediation=f"set network profiles interface-management-profile {pname} http no\n"
                            f"set network profiles interface-management-profile {pname} telnet no",
                auto_fixable=True, device=hostname))

    # weak admin password hashes
    raw = parsed.get("raw", "")
    weak_hash = re.findall(r"(phash>\$1\$|set mgt-config users \S+ phash \$1\$)", raw)
    if weak_hash:
        F.append(finding("PAN-008", "high", "Administrator password stored with weak MD5 hash ($1$)",
            "Old PAN-OS MD5-crypt hashes are brute-forceable; password should be reset on current PAN-OS to refresh the hash.",
            recommendation="Reset each administrator password (re-login will store the stronger modern hash).",
            remediation="! On CLI per admin: request password reset, then set new strong password",
            auto_fixable=False, device=hostname))

    # tls profiles
    for pname, ver in (flags.get("tls-min") or {}).items():
        if ver and ver in ("tls1-0", "tls1-1", "tls1-0-or-max"):
            F.append(finding("PAN-009", "medium",
                f"SSL-TLS profile '{pname}' permits TLS {ver.replace('tls1-', '1.')} or lower",
                "Legacy TLS versions are vulnerable to downgrade/POODLE-class attacks.",
                recommendation="Set minimum TLS 1.2.",
                remediation=f"set shared ssl-tls-service-profile {pname} protocol-settings min-version tls1-2",
                auto_fixable=True, device=hostname))

    if not parsed.get("rules"):
        F.append(finding("PAN-010", "info", "No security rules found in config",
            "The uploaded config contains no vsys security rulebase (management-only export?).",
            recommendation="Upload the full running configuration for a complete review.", device=hostname))
    return F


def improve(parsed, findings):
    raw = parsed["raw"]
    st = raw.lstrip()
    if st.startswith("<?xml") or st.startswith("<"):
        extra = [f["remediation"] for f in findings if f["auto_fixable"]]
        blob = raw.rstrip() + "\n"
        if extra:
            blob += ("<!-- ================= NetAI remediation set-commands (paste in CLI) =================\n"
                     + "\n".join(extra) + "\n-->\n")
        return blob
    # set-format: apply transforms + append
    out = []
    for line in raw.splitlines():
        if re.match(r"set deviceconfig system permitted-ip ", line.strip()) and any(
            f["rule_id"] == "PAN-004" for f in findings
        ):
            out.append("! [NetAI] " + line + "   (verify this management ACL is correct)")
            continue
        out.append(line)
    blob = "\n".join(out).rstrip() + "\n"
    extra = [f["remediation"] for f in findings if f["auto_fixable"]]
    if extra:
        blob += ("!================= NetAI remediation (review before applying) =================\n"
                 + "\n".join(extra) + "\n!=============================================================================\n")
    return blob
