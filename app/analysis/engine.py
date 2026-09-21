"""Analysis orchestrator: parse -> rules -> score -> topology -> summary."""
from . import aruba, cisco, fortinet, paloalto
from . import summary as summary_mod
from . import topology as topo_mod
from .common import SEV_WEIGHT, detect_vendor, finding, grade_for, file_sha256

VENDOR_MODULES = {
    "cisco": cisco,
    "paloalto": paloalto,
    "fortinet": fortinet,
    "aruba": aruba,
}
VENDOR_LABEL = {
    "cisco": "Cisco IOS/IOS-XE",
    "paloalto": "Palo Alto PAN-OS",
    "fortinet": "Fortinet FortiGate",
    "aruba": "Aruba AOS-CX/ArubaOS",
    "unknown": "Unknown vendor",
}

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def parse_file(text: str):
    """Auto-detect vendor and parse. Returns (vendor, device_dict)."""
    vendor = detect_vendor(text)
    mod = VENDOR_MODULES.get(vendor)
    if not mod:
        return vendor, {"vendor": vendor or "unknown", "hostname": "", "interfaces": [], "vlans": [],
                        "routes": [], "flags": {}, "raw": text}
    try:
        parsed = mod.parse(text)
    except Exception:
        parsed = {"vendor": vendor, "hostname": "", "interfaces": [], "vlans": [], "routes": [],
                  "flags": {}, "raw": text}
    return vendor, parsed


def analyze_files(items):
    """items: list of dicts {name, text}. Returns full result payload."""
    devices, findings, per_file = [], [], []
    for it in items:
        text = it["text"]
        vendor, parsed = parse_file(text)
        parsed["vendor"] = vendor
        parsed.setdefault("hostname", "")
        parsed["size"] = len(text)
        parsed["sha256"] = file_sha256(text)
        mod = VENDOR_MODULES.get(vendor)
        fnd = []
        if mod:
            try:
                fnd = mod.analyze(parsed)
            except Exception as e:  # never fail the whole analysis on one file
                fnd = [finding("SYS-ERR", "info", f"Parser issue on {it['name']}",
                               f"The file was detected as {vendor} but the rule engine hit an error: {e}",
                               recommendation="File uploaded successfully; review manually.", device=parsed.get("hostname") or it["name"])]
        else:
            fnd = [finding("SYS-UNK", "info", "Vendor could not be auto-detected",
                           "The file was stored but no vendor-specific rules were run.",
                           recommendation="Ensure the file is a full running/startup config of Palo Alto, Cisco, Fortinet or Aruba.",
                           device=it["name"])]
        dev_name = parsed.get("hostname") or it["name"]
        for f in fnd:
            f.setdefault("device", dev_name)
        devices.append(parsed)
        findings.extend(fnd)
        per_file.append({"name": it["name"], "vendor": vendor, "device": parsed, "findings": fnd})
    findings.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
    score = min(100, sum(SEV_WEIGHT.get(f["severity"], 0) for f in findings))
    topo = topo_mod.build_topology(devices)
    exec_summary = summary_mod.build(
        summary_doc_text=", ".join(sorted({d.get("vendor", "unknown") for d in devices})),
        devices=devices, findings=findings, score=score, grade=grade_for(score),
    )
    return {
        "devices": devices,
        "findings": findings,
        "score": score,
        "grade": grade_for(score),
        "topology": topo,
        "summary": exec_summary,
        "per_file": per_file,
    }
