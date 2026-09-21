"""Cisco IOS / IOS-XE parser + security rule engine."""
import re

from .common import finding, ip_interface, lines_with_ctx


def _section_lines(text, header_re):
    """Yield lines of every config section whose header matches header_re."""
    pat = re.compile(header_re, re.I)
    cur = None
    for _, s, raw in lines_with_ctx(text):
        st = s.strip()
        indent = len(s) - len(s.lstrip())
        if indent == 0:
            cur = pat.fullmatch(st) if pat.fullmatch(st) else None
            if cur is not None:
                yield st, []
            continue
        if cur is not None:
            yield None, [st]


def parse(text: str) -> dict:
    d = {
        "vendor": "cisco",
        "hostname": "",
        "model": "",
        "version": "",
        "interfaces": [],   # {name, ip, prefix, description, vlan_access, trunk_vlans, shutdown}
        "vlans": [],
        "routes": [],       # {dst, nexthop, iface}
        "flags": {},
        "raw": text,
    }
    cur_if = None
    cur_header = None  # section header for generic blocks
    for i, s, raw in lines_with_ctx(text):
        st = s.strip()
        indent = len(s) - len(s.lstrip())
        low = st.lower()

        if indent == 0:
            cur_if = None
            cur_header = None
            m = re.match(r"hostname\s+(\S+)", st, re.I)
            if m:
                d["hostname"] = m.group(1)
            m = re.match(r"version\s+([\d.()A-Za-z]+)", st, re.I)
            if m:
                d["version"] = m.group(1)
            m = re.match(r"vlan\s+(\d+)$", st, re.I)
            if m:
                d["vlans"].append({"id": int(m.group(1)), "name": ""})
                cur_header = ("vlan", int(m.group(1)))
                continue
            if re.match(r"vlan internal allocation", st, re.I):
                continue
            m = re.match(r"interface\s+(\S+)", st, re.I)
            if m:
                ifname = m.group(1)
                msvi = re.match(r"Vlan(\d+)$", ifname, re.I)
                cur_if = {
                    "name": ifname, "ip": None, "prefix": None, "description": "",
                    "vlan_access": int(msvi.group(1)) if msvi else None,
                    "trunk_vlans": [], "shutdown": False, "mode": "svi" if msvi else "",
                }
                d["interfaces"].append(cur_if)
                continue
            m = re.match(r"ip route(?:\s+vrf\s+\S+)?\s+(\S+)\s+(\S+)\s+(\S+)", st, re.I)
            if m:
                d["routes"].append({"dst": m.group(1), "mask": m.group(2), "nexthop": m.group(3), "iface": ""})
                continue
            for fl in ("aaa new-model", "service password-encryption", "ip http server",
                       "ip http secure-server", "ip source-route", "ip domain-name", "ip domain name",
                       "ip cef", "no ip domain-lookup", "logging buffered", "login block-for",
                       "ntp", "snmp-server community", "enable secret", "enable password",
                       "no ip http server", "crypto key generate", "ip ssh version", "banner motd",
                       "transport input", "access-class", "ip access-list", "access-list"):
                if low.startswith(fl):
                    key = fl.replace(" ", "_")
                    d["flags"].setdefault(key, []).append(st)
            continue

        # inside section
        if cur_if is not None:
            m = re.match(r"ip address (\S+)(?: (\S+))?", st, re.I)
            if m and not low.startswith("ip address dhcp"):
                iface = ip_interface(m.group(1), m.group(2))
                if iface:
                    cur_if["ip"], cur_if["prefix"] = str(iface.ip), iface.network.prefixlen
                continue
            m = re.match(r"description (.+)", st, re.I)
            if m:
                cur_if["description"] = m.group(1)[:120]
                continue
            if re.match(r"switchport mode trunk", st, re.I):
                cur_if["mode"] = "trunk"
                continue
            m = re.match(r"switchport access vlan (\d+)", st, re.I)
            if m:
                cur_if["vlan_access"] = int(m.group(1))
                continue
            m = re.match(r"switchport trunk allowed vlan (\S+)", st, re.I)
            if m:
                cur_if["trunk_vlans"] = m.group(1)
                continue
            if re.match(r"shutdown$", st, re.I):
                cur_if["shutdown"] = True
                continue
            if re.match(r"ip address dhcp", st, re.I):
                cur_if["ip"] = "dhcp"
            continue
        if cur_header and cur_header[0] == "vlan" and low.startswith("name "):
            for v in d["vlans"]:
                if v["id"] == cur_header[1]:
                    v["name"] = st[5:][:60]
            continue
    # normalise flag dict -> last value lists
    d["line_flags"] = [s for _, s, _ in lines_with_ctx(text)]
    return d


# --------------------------------------------------------------------- analysis rules
def analyze(parsed: dict):
    hostname = parsed.get("hostname") or "cisco-device"
    F = []
    lines = parsed.get("line_flags", [])
    joined = "\n".join(lines)
    flags = parsed.get("flags", {})

    def has(*pats):
        for p in pats:
            if re.search(p, joined, re.M | re.I):
                return True
        return False

    # enable password (weak) vs enable secret
    if has(r"^enable password "):
        F.append(finding("CIS-001", "high",
            "Legacy 'enable password' in use",
            "The enable password is stored with a reversible/weak (type 7 or plain) encoding. "
            "Anyone with the config can decrypt type-7 passwords in seconds.",
            evidence=[l for l in lines if l.lower().startswith("enable password")][:2],
            recommendation="Replace with 'enable secret' (type 8/9 hash) and delete the legacy line.",
            remediation="! Remove legacy enable password, set a strong secret (prompted on device)\n"
                        "configure terminal\n enable secret <NEW-STRONG-PASSWORD>\n no enable password\nend\n"
                        "! Prefer type 9: enable secret 9 <scrypt-hash>  (generate on-device: 'enable algorithm-type scrypt secret ...')",
            auto_fixable=True, device=hostname))

    # username with type 7 password
    weak_user = [l for l in lines if re.search(r"^username \S+ (password|secret [07]) ", l, re.I)]
    if weak_user:
        F.append(finding("CIS-002", "high",
            "Local user credentials stored as type 7 / plaintext",
            "Type 7 passwords are trivially reversible; plaintext is worse. Local accounts must use hashed secrets.",
            evidence=weak_user[:4],
            recommendation="Recreate users with 'username X secret <pw>' (type 8/9) and remove password-based entries.",
            remediation="configure terminal\n"
                        " username <user> algorithm-type scrypt secret <NEW-PASSWORD>\n"
                        " no username <user> password <old>\nend",
            auto_fixable=False, device=hostname))

    # telnet on vty
    telnet = [l for l in lines if re.match(r"transport input .*(telnet|all)\s*$", l.strip(), re.I)]
    if telnet:
        F.append(finding("CIS-003", "critical",
            "Telnet management access enabled",
            "Telnet transmits credentials and all traffic in cleartext. Full device takeover is possible via MITM/sniffing.",
            evidence=telnet[:3],
            recommendation="Restrict VTY transport to SSH only.",
            remediation="line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh",
            auto_fixable=True, device=hostname))

    # vty ACL
    vty_block = re.search(r"(?ms)^line vty.*?(?=^\S|\Z)", joined)
    if vty_block and "access-class" not in vty_block.group(0):
        F.append(finding("CIS-004", "high",
            "VTY lines not protected by management ACL",
            "Any routable host can attempt to authenticate to the device. A management ACL limits exposure to admin subnets.",
            evidence=vty_block.group(0).splitlines()[:6],
            recommendation="Apply 'access-class <acl> in' on all VTY lines with an ACL permitting only management subnets.",
            remediation="ip access-list standard MGMT-HOSTS\n permit 10.99.0.0 0.0.0.255\n deny any\n!\n"
                        "line vty 0 4\n access-class MGMT-HOSTS in\nline vty 5 15\n access-class MGMT-HOSTS in",
            auto_fixable=True, device=hostname))

    # aaa
    if not has(r"^aaa new-model"):
        F.append(finding("CIS-005", "medium",
            "AAA not enabled",
            "Without AAA, authentication/authorization/accounting is ad-hoc; centralised control and audit trails are lost.",
            recommendation="Enable AAA and integrate TACACS+/RADIUS with local fallback.",
            remediation="aaa new-model\naaa authentication login default group tacacs+ local\n"
                        "aaa authorization commands 15 default group tacacs+ local\n"
                        "aaa accounting exec default start-stop group tacacs+\ntacacs server TAC1\n"
                        " address ipv4 10.99.0.10\n key 7 <encrypted-key>",
            auto_fixable=True, device=hostname))

    # http server
    if has(r"^ip http server") and not has(r"^no ip http server"):
        F.append(finding("CIS-006", "high",
            "Insecure web management (HTTP) enabled",
            "The built-in HTTP server sends credentials in cleartext and expands the attack surface (CVE history on IOS HTTP).",
            evidence=[l for l in lines if l.lower().startswith("ip http server")][:2],
            recommendation="Disable HTTP, keep HTTPS only with strong ciphers and ACL.",
            remediation="no ip http server\nip http secure-server\nip http access-class MGMT-HOSTS",
            auto_fixable=True, device=hostname))

    # snmp communities
    snmp = [l for l in lines if re.match(r"snmp-server community ", l, re.I)]
    bad_snmp = [l for l in snmp if re.search(r"(public|private|\bro\b( |\s*$)|\brw\b)", l, re.I)]
    if bad_snmp:
        F.append(finding("CIS-007", "high",
            "Insecure SNMP communities (default or RW without ACL)",
            "Default ('public'/'private') or ACL-less SNMP communities allow enumeration or, with RW, full config pull/push.",
            evidence=bad_snmp[:4],
            recommendation="Remove default communities; deploy SNMPv3 with auth+priv and a polling ACL.",
            remediation="no snmp-server community public\nno snmp-server community private\n"
                        "snmp-server group NETOPS v3 priv\nsnmp-server user poller NETOPS v3 auth sha <AUTH-PW> priv aes 128 <PRIV-PW>\n"
                        "snmp-server host 10.99.0.20 version 3 priv poller",
            auto_fixable=False, device=hostname))

    # ssh
    if not has(r"^ip ssh version 2"):
        F.append(finding("CIS-008", "medium",
            "SSH not locked to version 2",
            "SSHv1 has known integrity/MIIM weaknesses; IOS may still negotiate v1 unless pinned.",
            recommendation="Pin SSH to v2 and generate >=2048-bit RSA keys.",
            remediation="ip ssh version 2\nip ssh time-out 60\nip ssh authentication-retries 3\n"
                        "crypto key generate rsa modulus 4096",
            auto_fixable=True, device=hostname))

    # weak rsa key
    if has(r"crypto key generate rsa modulus (?!([2-9]\d{3,}))") or (
        has(r"crypto key generate rsa") and not has(r"modulus")
    ):
        F.append(finding("CIS-009", "medium", "Weak or unspecified RSA key size",
            "Keys < 2048 bits (or unverified defaults of 512/768) are brute-forceable; modern clients will refuse them.",
            recommendation="Regenerate host keys at 2048+ bits.",
            remediation="crypto key zeroize rsa\ncrypto key generate rsa modulus 4096", auto_fixable=False, device=hostname))

    # login block
    if not has(r"^login block-for"):
        F.append(finding("CIS-010", "medium", "No brute-force protection on login",
            "Without 'login block-for' the device accepts unlimited credential guesses.",
            recommendation="Enable quiet-mode after repeated failures + slothold.",
            remediation="login block-for 120 attempts 3 within 60\nlogin quiet-mode access-class MGMT-HOSTS",
            auto_fixable=True, device=hostname))

    # console / vty idle timeout
    vtyb = vty_block.group(0) if vty_block else ""
    if "exec-timeout" not in vtyb:
        F.append(finding("CIS-011", "low", "No idle timeout on VTY lines",
            "Abandoned management sessions stay open indefinitely, risking unattended privileged access.",
            recommendation="Set exec-timeout to 10 minutes or less on all lines.",
            remediation="line vty 0 4\n exec-timeout 10 0\nline con 0\n exec-timeout 10 0",
            auto_fixable=True, device=hostname))

    # ntp
    if not has(r"^ntp server |^ntp peer |^sntp server "):
        F.append(finding("CIS-012", "medium", "No trusted NTP sources",
            "Without synchronised time, logs cannot be correlated and certificates/protocols misbehave.",
            recommendation="Point the device at internal (or authenticated) NTP servers.",
            remediation="ntp server 10.99.0.5 prefer\nntp server 10.99.0.6\nntp source Loopback0",
            auto_fixable=True, device=hostname))

    # logging
    if not has(r"^logging host |^logging buffered \d"):
        F.append(finding("CIS-013", "medium", "No central logging destination",
            "Security events are lost on reboot and invisible to the SOC without syslog/SNMP trap destinations.",
            recommendation="Ship logs to a collector at appropriate level with timestamps.",
            remediation="logging host 10.99.0.30\nlogging trap informational\nlogging buffered 64000 debugging\n"
                        "service timestamps log datetime msec show-timezone",
            auto_fixable=True, device=hostname))

    # legacy services
    legacy = [l for l in lines if re.match(r"^(ip source-route|ip finger|ip bootp server|service pad|ip identd)", l, re.I)]
    if legacy:
        F.append(finding("CIS-014", "medium", "Legacy IP services enabled",
            "Source-routing, bootp, finger and PAD are obsolete services that leak information or allow spoofing abuse.",
            evidence=legacy[:5],
            recommendation="Disable all legacy services globally.",
            remediation="no ip source-route\nno ip finger\nno ip bootp server\nno service pad\nno ip identd",
            auto_fixable=True, device=hostname))

    # any-any ACL early
    acl_lines = [l for l in lines if re.match(r"(access-list \d+ permit|permit) ip any any", l, re.I)]
    if acl_lines:
        F.append(finding("CIS-015", "high", "Permit-any catch-all in ACLs",
            "A 'permit ip any any' rule neutralises the ACL that contains it - traffic the rule above it denied is still allowed.",
            evidence=acl_lines[:3],
            recommendation="Replace catch-all with explicit permitted subnets and an explicit 'deny ip any any' log.",
            remediation="! Example rewrite:\nip access-list extended <ACL-NAME>\n permit tcp 10.0.0.0 0.255.255.255 any eq 443\n"
                        " deny ip any any log",
            auto_fixable=False, device=hostname))

    # banner
    if not has(r"^banner (motd|login)"):
        F.append(finding("CIS-016", "info", "No legal banner configured",
            "A login banner is a low-cost legal/forensic control notifying users of monitoring.",
            recommendation="Configure a MOTD/login banner.",
            remediation="banner motd ^C Authorized access only. All activity is monitored and reported. ^C",
            auto_fixable=True, device=hostname))

    # password-encryption dependency
    if has(r"^service password-encryption") and not weak_user:
        F.append(finding("CIS-017", "low", "Reliance on type-7 password encryption",
            "'service password-encryption' only obfuscates; type-7 is reversible. Use secret (hashed) forms everywhere.",
            recommendation="Migrate all type-7 passwords to hashed secrets (username secret / enable secret / key config-key).",
            remediation="! Migrate credentials to hashed forms, then this line can stay as last-resort fallback",
            auto_fixable=False, device=hostname))

    return F


def improve(parsed: dict, findings) -> str:
    """Produce an improved config: safe line transforms + appended remediation block."""
    raw = parsed["raw"]
    out = []
    drop_prefixes = ("enable password",)
    for rawline in raw.splitlines():
        s = rawline.strip()
        low = s.lower()
        if any(low.startswith(p) for p in drop_prefixes):
            out.append("! [NetAI] removed: " + s + "  (replaced by enable secret)")
            continue
        if re.match(r"^transport input .*(telnet|all)", s, re.I):
            indent = rawline[: len(rawline) - len(rawline.lstrip())]
            out.append(indent + "transport input ssh" + "   ! [NetAI] was: " + s)
            continue
        if re.match(r"^ip http server$", s, re.I):
            out.append("no ip http server" + "   ! [NetAI] was: " + s)
            out.append("ip http secure-server")
            continue
        if re.match(r"^snmp-server community (public|private)\b", s, re.I):
            out.append("no " + s + "   ! [NetAI] default community removed")
            continue
        if re.match(r"^(ip source-route|ip finger|ip bootp server|service pad|ip identd)", s, re.I):
            out.append("no " + s + "   ! [NetAI] legacy service disabled")
            continue
        out.append(rawline)
    blob = "\n".join(out).rstrip() + "\n"
    extra = []
    for f in findings:
        if f["auto_fixable"] and f["rule_id"] not in (
            "CIS-001", "CIS-003", "CIS-006", "CIS-014",  # handled by transforms above
        ):
            extra.append("! --- " + f["rule_id"] + ": " + f["title"] + " ---\n" + f["remediation"])
    if extra:
        blob += ("\n!================= NetAI remediation (review before applying) =================\n"
                 + "\n!\n".join(extra) + "\n!=============================================================================\n")
    return blob
