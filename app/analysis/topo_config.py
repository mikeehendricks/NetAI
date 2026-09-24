"""Topology-to-configuration generator.

Turns a topology graph ({"nodes": [...], "links": [...]}, the same shape the
low-level topology view renders) into hardened, ready-to-review device
configuration files. Sources of topology:

  * an analysed project's computed topology (offline, deterministic)
  * an uploaded topology IMAGE, parsed by the configured AI vision provider
    (same OpenAI/Anthropic-compatible settings as the AI summary enhancer)

No third-party dependencies beyond what NetAI already ships.
"""
import base64
import json
import logging
import re

import requests

from . import ai as ai_mod

log = logging.getLogger("netai.topoconfig")

MAX_DEVICES = 60
MAX_LINKS = 300

SUPPORTED_VENDORS = ("cisco", "paloalto", "fortinet", "aruba")

IMAGE_MIME = {"image/png": "png", "image/jpeg": "jpeg"}
IMG_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
)

VISION_PROMPT = (
    "You are a network engineer. Study the network topology diagram image and "
    "extract every device and link. Return ONLY a JSON object, no prose, no code "
    "fences, matching exactly this schema:\n"
    '{"devices": [{"name": "device-hostname", "vendor": "cisco|paloalto|fortinet|aruba", '
    '"role": "router|firewall|switch", "interfaces": [{"name": "Ethernet0/1", "ip": "10.0.0.1/30", '
    '"peer": "other-device-name"}], "notes": ""}],\n'
    ' "links": [{"a": "device-or-subnet-name", "b": "device-or-subnet-name", "ip": "cidr-on-a-or-empty"}]}\n'
    "Rules: use the labels written in the diagram verbatim for names; map vendor names to the four "
    "allowed values (unknown -> cisco); include subnets as links entries when drawn; if an IP or mask "
    "is written next to an interface, include it; omit anything unreadable rather than guessing."
)


def sniff_image(data: bytes):
    """Return (mime, kind) when the bytes really are a PNG/JPEG, else None."""
    for magic, mime in IMG_MAGIC:
        if data.startswith(magic):
            return mime, mime.split("/")[1]
    return None


# --------------------------------------------------------------------- vision
def vision_available(cfg) -> bool:
    if not ai_mod.ai_available(cfg):
        return False
    # Local/Ollama ('custom') installs run separate vision and text models, and a
    # text-only local model cannot read images. setup-local-ai.sh omits
    # OPENAI_VISION_MODEL when no vision model passed the live load-test, so the
    # UI must treat a missing key as "manual mode", not silently try OPENAI_MODEL.
    # Cloud providers keep the fallback (their default chat models accept images).
    if (cfg.get("AI_PROVIDER") or "").lower() == "custom":
        return bool(cfg.get("OPENAI_VISION_MODEL"))
    return True


def extract_topology_from_image(cfg, data: bytes, mime: str):
    """Ask the configured AI vision provider to turn the diagram into topology.
    Returns {"devices": [...], "links": [...]} normalized like build_topology().
    Raises ValueError with a friendly message on any failure."""
    if not ai_mod.ai_available(cfg):
        raise ValueError("AI vision is not configured. Set AI_PROVIDER and the matching API key in .env.")
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Image is larger than 8 MB.")
    b64 = base64.b64encode(data).decode("ascii")
    provider = (cfg.get("AI_PROVIDER") or "").lower()
    try:
        if provider == "anthropic":
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": cfg["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": cfg.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
                      "max_tokens": 3000,
                      "messages": [{"role": "user", "content": [
                          {"type": "image", "source": {"type": "base64", "media_type": mime, "data": b64}},
                          {"type": "text", "text": VISION_PROMPT},
                      ]}]},
                timeout=int(cfg.get("AI_VISION_TIMEOUT") or 90))
            r.raise_for_status()
            text = r.json()["content"][0]["text"]
        else:  # openai or custom (must be a vision-capable model, e.g. gpt-4o)
            base = (cfg.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
            r = requests.post(
                base + "/chat/completions",
                headers={"Authorization": "Bearer " + cfg["OPENAI_API_KEY"],
                         "Content-Type": "application/json"},
                json={"model": cfg.get("OPENAI_VISION_MODEL", cfg.get("OPENAI_MODEL", "gpt-4o")),
                      "messages": [{"role": "user", "content": [
                          {"type": "text", "text": VISION_PROMPT},
                          {"type": "image_url",
                           "image_url": {"url": f"data:{mime};base64,{b64}"}},
                      ]}, ],
                      "temperature": 0.1, "max_tokens": 3000},
                timeout=int(cfg.get("AI_VISION_TIMEOUT") or 90))
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
    except Exception as e:  # network/API errors -> friendly message
        log.warning("vision extraction failed: %s", e)
        raise ValueError("The AI vision provider could not process the image. Check the API key/model in .env.")

    return _parse_vision_json(text)


def _parse_vision_json(text: str):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("The AI response did not contain topology data. Try a clearer diagram.")
    try:
        raw = json.loads(m.group(0))
    except json.JSONDecodeError:
        raise ValueError("The AI returned malformed topology data. Try again or use a clearer diagram.")
    devices, byname = [], {}
    for d in (raw.get("devices") or [])[:MAX_DEVICES]:
        if not isinstance(d, dict):
            continue
        name = _safe_name(d.get("name") or "", "device", len(devices) + 1)
        vendor = str(d.get("vendor") or "cisco").lower()
        if vendor not in SUPPORTED_VENDORS:
            vendor = "cisco"
        role = str(d.get("role") or "router").lower()
        if role not in ("router", "firewall", "switch"):
            role = "router"
        ifaces = []
        for i in (d.get("interfaces") or [])[:40]:
            if not isinstance(i, dict):
                continue
            iname = _safe_name(i.get("name") or "", "if", len(ifaces) + 1, maxlen=32)
            ip = str(i.get("ip") or "")[:64]
            if _looks_like_ip(ip):
                ifaces.append({"name": iname, "ip": ip})
        # drop pure-noise entries: no real name AND nothing useful attached
        if not str(d.get("name") or "").strip() and not ifaces:
            continue
        dev = {"name": name, "vendor": vendor, "role": role, "interfaces": ifaces}
        devices.append(dev)
        byname[name.lower()] = dev
    links = []
    for l in (raw.get("links") or [])[:MAX_LINKS]:
        if not isinstance(l, dict):
            continue
        a, b = str(l.get("a") or ""), str(l.get("b") or "")
        if not a or not b or a.lower() == b.lower():
            continue
        ip = str(l.get("ip") or "")[:64]
        links.append({"a": a, "b": b, "ip": ip if _looks_like_ip(ip) else ""})
    if not devices:
        raise ValueError("No devices could be recognized in the image. Try a higher-resolution diagram.")
    return {"devices": devices, "links": links}


def _safe_name(s, prefix, idx, maxlen=48):
    s = re.sub(r"[^A-Za-z0-9._-]", "-", str(s)).strip("-")[:maxlen]
    return s or f"{prefix}-{idx}"


def _looks_like_ip(s):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", s))


# ------------------------------------------------------------------ generator
def generate_from_topology(topo):
    """topo: {'nodes': [{id,kind,label,meta}], 'links': [...]} (build_topology shape)
    OR the image-extracted {'devices': [...], 'links': [...]} shape.
    Returns a list of {'filename','vendor','hostname','config'} dicts."""
    devices = topo.get("devices")
    if devices is None:
        devices, links = _devices_from_graph(topo)
    else:
        devices, links = devices, topo.get("links", [])
    out = []
    for i, d in enumerate(devices[:MAX_DEVICES]):
        vendor = d.get("vendor") if d.get("vendor") in SUPPORTED_VENDORS else "cisco"
        hostname = _safe_name(d.get("name") or d.get("label") or "", "device", i + 1, maxlen=64)
        gen = {"cisco": _cisco, "paloalto": _paloalto,
               "fortinet": _fortinet, "aruba": _aruba}[vendor]
        cfg_text = gen(hostname, d, devices, links)
        out.append({
            "filename": f"{_safe_name(hostname, 'device', i + 1, maxlen=40)}.{'set' if vendor == 'paloalto' else 'cfg'}",
            "vendor": vendor,
            "hostname": hostname,
            "config": cfg_text,
        })
    return out


def _devices_from_graph(topo):
    nodes = topo.get("nodes", []) or []
    links = topo.get("links", []) or []
    devices = []
    for n in nodes:
        if n.get("kind") in ("firewall", "router", "switch", "device"):
            meta = n.get("meta") or {}
            ifaces = [{"name": str(i.get("name", ""))[:32], "ip": str(i.get("ip", ""))[:64]}
                      for i in (meta.get("interfaces") or []) if _looks_like_ip(str(i.get("ip", "")))]
            devices.append({"name": n.get("label") or n.get("id"), "vendor": (meta.get("vendor") or "").lower(),
                            "role": n.get("kind"), "interfaces": ifaces})
    return devices, links


def _ifaces_for(dev):
    return [(str(i.get("name") or f"Gi0/{n}"), str(i.get("ip"))) for n, i in enumerate(dev.get("interfaces") or [])]


def _common_footer_notes(vendor):
    return (
        "! ---------------------------------------------------------------------\n"
        "! Generated by NetAI from the reviewed topology. Review before apply:\n"
        "! addresses, routing and credentials must match your standards.\n"
        "! Security baseline mirrors the NetAI rule set (management hardening).\n"
        "! ---------------------------------------------------------------------\n"
    )


def _cisco(host, dev, devices, links):
    ifs = _ifaces_for(dev)
    lines = [
        f"! Hardened baseline generated by NetAI for {host}",
        "hostname " + host,
        "no ip domain-lookup",
        "ip domain-name example.local",
        "service password-encryption",
        "no service pad",
        "no ip http server",
        "ip http secure-server",   # HTTPS-only management
        "enable secret 5 <replace-with-hashed-secret>",
        "username netadmin privilege 15 secret <replace-with-strong-password>",
        "aaa new-model",
        "aaa authentication login default TACACS+ local",
        "aaa authorization exec default TACACS+ local",
        "ip ssh version 2",
        "crypto key generate rsa modulus 4096",
        "line vty 0 4",
        " transport input ssh",
        " exec-timeout 10 0",
        " access-class MGMT-HOSTS in",
        "line con 0",
        " exec-timeout 10 0",
        "no snmp-server community public",
        "no snmp-server community private",
        "snmp-server group NETMON v3 priv",
        "ntp server 10.0.0.1 prefer        ! TODO point at your internal NTP",
        "logging host 10.0.0.2             ! TODO point at your syslog collector",
        "logging buffered 16386 informational",
        "banner login ^C Authorized access only. All activity is monitored and logged.^C",
        "!",
    ]
    for name, ip in ifs:
        lines += [f"interface {name}", f" description link per topology", f" ip address {ip}",
                  " no shutdown", "!"]
    if not ifs:
        lines += ["! TODO: no interfaces were readable in the topology - add them here.", "!"]
    lines += [
        "ip access-list standard MGMT-HOSTS",
        " permit 10.0.0.0 0.255.255.255    ! TODO restrict to your management subnet",
        " deny   any",
        "!",
        "end",
    ]
    return "\n".join(lines) + "\n" + _common_footer_notes("cisco")


def _paloalto(host, dev, devices, links):
    ifs = _ifaces_for(dev)
    lines = [
        f"// Hardened baseline generated by NetAI for {host}",
        "set deviceconfig system hostname " + host,
        "set deviceconfig system timezone UTC",
        "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.0.0.1  ! TODO internal NTP",
        "set deviceconfig system syslog server NETLOG server 10.0.0.2 facility LOG_USER  ! TODO collector",
        "set deviceconfig system permitted-ip 10.0.0.0/8   ! TODO restrict management access",
        "set mgt-config users admin phash <replace-with-hash>",
        "set deviceconfig setting management admin-lockout failed-attempts 5 lockout-time 30",
        "set shared log-settings syslog NETLOG server profile",
        "set network interface ethernet ethernet1/1 comment 'per topology'",
    ]
    for n, (name, ip) in enumerate(ifs, start=1):
        eth = name if name.lower().startswith("ethernet") else f"ethernet1/{n}"
        if "/" in ip:
            addr, mask = ip.split("/", 1)
            lines.append(f"set network interface ethernet {eth} layer3 ip {addr} mask {mask}")
        lines.append(f"set zone NETWORK zone L3-{n} network layer3 {eth}")
    if not ifs:
        lines.append("// TODO: no interfaces were readable in the topology - add them here.")
    lines += [
        "set deviceconfig setting session tcp-reject-non-syn yes",
        "set rulebase security rules PER-APP-ACTION from any to any source-user any application any  ! replace any/any with least privilege",
        "// Reminder: NetAI flags 'any/any' rules as critical - model least privilege here.",
        "// end of generated baseline",
    ]
    return "\n".join(lines) + "\n" + _common_footer_notes("paloalto")


def _fortinet(host, dev, devices, links):
    ifs = _ifaces_for(dev)
    lines = [
        f"# Hardened baseline generated by NetAI for {host}",
        "config system global",
        f'    set hostname "{host}"',
        "    set admin-sport 443",
        "    set strong-crypto enable",
        "    set admin-lockout-threshold 5",
        "    set admin-lockout-duration 1800",
        "end",
        "config system admin",
        "    edit \"netadmin\"",
        "        set accprofile super_admin",
        "        set passwd <replace-with-strong-password>",
        "    next",
        "    edit \"admin\"",
        "        set trusthost1 10.0.0.0 255.0.0.0   ! TODO restrict management hosts",
        "    next",
        "end",
        "config log syslogd setting",
        "    set status enable",
        "    set server \"10.0.0.2\"              ! TODO collector",
        "    set mode reliable",
        "end",
        "config system ntp",
        "    set ntpsync enable",
        '    set server1 "10.0.0.1"              ! TODO internal NTP',
        "end",
    ]
    for n, (name, ip) in enumerate(ifs, start=1):
        port = name if name.lower().startswith(("port", "wan", "dmz")) else f"port{n}"
        lines += [f"config system interface", f"    edit \"{port}\"",
                  f"        set ip {ip.replace('/', ' ')}" if "/" in ip else f"        # ip per topology",
                  "        set allowaccess ping https ssh", "    next", "end"]
    if not ifs:
        lines.append("# TODO: no interfaces were readable in the topology - add them here.")
    lines += ["config system settings",
              "    set deny-tcp-with-icmp enable",
              "end",
              "# Reminder: replace any/any firewall policies with least privilege.",
              "end"]
    return "\n".join(lines) + "\n" + _common_footer_notes("fortinet")


def _aruba(host, dev, devices, links):
    ifs = _ifaces_for(dev)
    lines = [
        f"; Hardened baseline generated by NetAI for {host}",
        f"hostname {host}",
        "web-management ssl",
        "no web-management http",
        "no telnet-server",
        "ssh version 2",
        "password manager user-name netadmin sha256 plaintext <replace-with-strong-password>",
        "snmp-server community NETMON restricted    ! TODO replace with SNMPv3",
        "no snmp-server community public",
        "timesync ntp",
        "ntp unicast",
        "ntp server 10.0.0.1                        ! TODO internal NTP",
        "logging 10.0.0.2                           ! TODO collector",
        "banner motd Authorized access only. All activity is monitored and logged.",
        "aaa authentication login default local     ! TODO move to TACACS+/RADIUS",
        "aaa authentication ssh login public-key  ! prefer key-based SSH",
        "!",
    ]
    for name, ip in ifs:
        lines += [f"interface {name}", f"   ip address {ip}", "   no shutdown", "!"]
    if not ifs:
        lines += ["; TODO: no interfaces were readable in the topology - add them here.", "!"]
    lines += ["ip authorized-managers 10.0.0.0 255.0.0.0 access manager  ! TODO restrict",
              "end"]
    return "\n".join(lines) + "\n" + _common_footer_notes("aruba")
