"""Shared analysis helpers: finding model, vendor detection, parsing utilities."""
import hashlib
import ipaddress
import re

# severity -> weight for the 0-100 risk score
SEV_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def finding(rule_id, severity, title, description, evidence=None, recommendation="",
            remediation="", auto_fixable=False, device=""):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence or [],
        "recommendation": recommendation,
        "remediation": remediation,
        "auto_fixable": auto_fixable,
        "device": device,
    }


def detect_vendor(text: str) -> str:
    """Return one of: paloalto, fortinet, cisco, aruba, unknown."""
    low = text.lower()
    head = low[:4000]
    scores = {"paloalto": 0, "fortinet": 0, "cisco": 0, "aruba": 0}

    # --- Palo Alto
    if head.lstrip().startswith("<?xml") or "<config " in head or "<config>" in head:
        if "palo" in low[:2000] or "version" in low:
            scores["paloalto"] += 6
    if re.search(r"^set (deviceconfig|rulebase|network interface ethernet|mgt-config)", low, re.M):
        scores["paloalto"] += 6
    if "pan-os" in low or "set deviceconfig system" in low:
        scores["paloalto"] += 4

    # --- Fortinet
    if re.search(r"^config system global", low, re.M):
        scores["fortinet"] += 6
    if re.search(r"^config firewall policy", low, re.M) or re.search(r"^config firewall addr", low, re.M):
        scores["fortinet"] += 5
    if re.search(r"config-version=FG", low) or re.search(r"fgt", low[:500]):
        scores["fortinet"] += 3
    if re.search(r'^edit "?port\d+"?', low, re.M):
        scores["fortinet"] += 2

    # --- Cisco IOS / IOS-XE
    if re.search(r"^(enable secret|service password-encryption|line vty|line con)", low, re.M):
        scores["cisco"] += 5
    if re.search(r"^interface (Gigabit|Fast|Ten|TwentyFive|Forty|Tunnel|Serial|Vlan|Loopback|Port-channel)", low, re.M | re.I):
        scores["cisco"] += 5
    if re.search(r"^(router (ospf|eigrp|bgp)|ip route |spanning-tree mode|aaa new-model)", low, re.M):
        scores["cisco"] += 3
    if re.search(r"ios version|boot system flash|cisco ios", low):
        scores["cisco"] += 2

    # --- Aruba (AOS-CX / AOS-S / ArubaOS)
    if re.search(r"^interface (1/1/|2/1/|3/1/)\d", low, re.M):
        scores["aruba"] += 6
    if re.search(r"^(aruba-central|vsf member|aaa authentication login|aaa authorization)", low, re.M):
        scores["aruba"] += 3
    if re.search(r"(wlan ssid-profile|wlan virtual-ap|mgmt-user |arubacx|aruba os)", low):
        scores["aruba"] += 4
    if re.search(r"^web-management", low, re.M) or re.search(r"^ip authorized-managers", low, re.M):
        scores["aruba"] += 4

    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else "unknown"


# --------------------------------------------------------------------- parsing helpers
def strip_comments(line: str) -> str:
    """Remove common trailing comments (! for cisco, # for forti/aruba when leading)."""
    s = line.rstrip()
    if s.lstrip().startswith(("!", "#")):
        return ""
    return s


def classful_mask_to_prefix(mask: str):
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return None


def ip_interface(ip_str, mask_str=None):
    """Build ipaddress.IPv4Interface from 'a.b.c.d' + dotted mask or cidr string."""
    try:
        if mask_str:
            if "/" in ip_str:
                return ipaddress.ip_interface(ip_str)
            pl = classful_mask_to_prefix(mask_str)
            if pl is None:
                return None
            return ipaddress.ip_interface(f"{ip_str}/{pl}")
        return ipaddress.ip_interface(ip_str)
    except ValueError:
        return None


def lines_with_ctx(text: str):
    """Yield (index0, line_without_comment, raw_line) skipping empty/comment lines."""
    for i, raw in enumerate(text.splitlines()):
        s = strip_comments(raw)
        if s.strip():
            yield i, s, raw


def file_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def grade_for(score: int) -> str:
    if score <= 9:
        return "A"
    if score <= 25:
        return "B"
    if score <= 45:
        return "C"
    if score <= 65:
        return "D"
    if score <= 85:
        return "E"
    return "F"
