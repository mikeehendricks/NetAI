"""Low-level (L2/L3) topology inference from parsed device configs."""
import ipaddress


def _device_kind(dev) -> str:
    vendor = dev.get("vendor", "")
    if vendor in ("paloalto", "fortinet"):
        return "firewall"
    has_routes = bool(dev.get("routes"))
    l3 = [i for i in dev.get("interfaces", []) if i.get("ip")]
    vlans = dev.get("vlans", [])
    if vendor == "cisco":
        if has_routes and l3:
            return "router"
        if vlans or any(i.get("vlan_access") or i.get("mode") == "trunk" for i in dev.get("interfaces", [])):
            return "switch"
        return "router" if l3 else "switch"
    if vendor == "aruba":
        return "switch"
    return "router" if l3 else "device"


def _iface_label(dev_idx, iface):
    return f"{iface['name']}"


def build_topology(devices):
    """devices: list of parsed device dicts. Returns graph dict for the SVG renderer."""
    nodes, links = [], []
    node_ids = set()
    seg_of_net = {}      # ip_network -> segment node id
    vlan_color_seed = {}

    def add_node(nid, kind, label, meta=None):
        if nid in node_ids:
            return nid
        node_ids.add(nid)
        nodes.append({"id": nid, "kind": kind, "label": label, "meta": meta or {}})
        return nid

    # ---- device nodes
    for idx, dev in enumerate(devices):
        hostname = dev.get("hostname") or f"{dev.get('vendor','device')}-{idx+1}"
        kind = _device_kind(dev)
        add_node(f"dev{idx}", kind, hostname, {
            "vendor": dev.get("vendor"), "version": dev.get("version", ""),
            "interfaces": [
                {"name": i.get("name"), "ip": (i.get("ip") + "/" + str(i["prefix"])) if i.get("ip") and i.get("prefix") is not None else (i.get("ip") or ""),
                 "desc": i.get("description", ""), "vlan": i.get("vlan_access"),
                 "mode": i.get("mode", ""), "down": i.get("shutdown", False)}
                for i in dev.get("interfaces", [])
            ],
            "vlans": dev.get("vlans", []),
            "routes": [
                {"dst": r.get("dst") + (" " + r.get("mask", "") if r.get("mask") else ""), "via": r.get("nexthop", "")}
                for r in dev.get("routes", [])
            ],
        })

    # ---- L3 interface -> subnet segments
    for idx, dev in enumerate(devices):
        hostname = dev.get("hostname") or f"device-{idx+1}"
        for iface in dev.get("interfaces", []):
            ip, prefix = iface.get("ip"), iface.get("prefix")
            if not ip or ip == "dhcp" or prefix is None:
                continue
            try:
                itf = ipaddress.ip_interface(f"{ip}/{prefix}")
            except ValueError:
                continue
            net = str(itf.network)
            if net not in seg_of_net:
                seg_of_net[net] = add_node(f"seg-{net}", "subnet", net,
                                           {"network": net, "vlan": iface.get("vlan_access")})
                if iface.get("vlan_access"):
                    vlan_color_seed[iface["vlan_access"]] = True
            links.append({
                "source": f"dev{idx}", "target": seg_of_net[net], "kind": "l3",
                "label": _iface_label(idx, iface), "network": net, "vlan": iface.get("vlan_access"),
                "ip": f"{ip}/{prefix}",
            })

    # ---- default routes -> internet cloud / WAN gateway
    cloud_added = False
    for idx, dev in enumerate(devices):
        for r in dev.get("routes", []):
            dst = (r.get("dst") or "").split()[0]
            nh = r.get("nexthop", "")
            # nosec B104 below: "0.0.0.0" literals are routing-table data, not binds
            is_default = dst in ("0.0.0.0", "0.0.0.0/0") or (  # nosec B104 - routing data
                dst == "0.0.0.0" and r.get("mask") in ("0.0.0.0", "", None))  # nosec B104
            if not is_default:
                continue
            if not cloud_added:
                add_node("wan", "cloud", "Internet / WAN", {"role": "upstream"})
                cloud_added = True
            # find which local interface subnet contains the next-hop
            via_iface = ""
            for iface in dev.get("interfaces", []):
                ip, prefix = iface.get("ip"), iface.get("prefix")
                if not ip or prefix is None:
                    continue
                try:
                    itf = ipaddress.ip_interface(f"{ip}/{prefix}")
                    if nh and ipaddress.ip_address(nh) in itf.network:
                        via_iface = iface["name"]
                        break
                except ValueError:
                    continue
            links.append({
                "source": f"dev{idx}", "target": "wan", "kind": "wan",
                "label": f"default via {nh}" + (f" ({via_iface})" if via_iface else ""),
                "network": "0.0.0.0/0", "vlan": None, "ip": "",
            })

    # ---- L2 access ports: group by VLAN on switching devices
    vlan_segments = {}
    for idx, dev in enumerate(devices):
        if dev.get("vendor") not in ("cisco", "aruba"):
            continue
        for iface in dev.get("interfaces", []):
            if iface.get("ip"):
                continue
            vlan = iface.get("vlan_access")
            if not vlan or iface.get("shutdown"):
                continue
            sid = f"vlan{vlan}"
            if sid not in vlan_segments:
                vlan_name = next((v.get("name", "") for v in dev.get("vlans", []) if v.get("id") == vlan), "")
                vlan_segments[sid] = add_node(
                    sid, "vlan", f"VLAN {vlan}" + (f" ({vlan_name})" if vlan_name else ""),
                    {"vlan": vlan, "name": vlan_name})
                vlan_color_seed[vlan] = True
            links.append({
                "source": f"dev{idx}", "target": vlan_segments[sid], "kind": "l2",
                "label": iface["name"], "network": f"vlan{vlan}", "vlan": vlan, "ip": "",
            })

    # ---- de-duplicate parallel links (same endpoints+label)
    seen, uniq = set(), []
    for l in links:
        key = (l["source"], l["target"], l["label"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(l)
    return {
        "nodes": nodes,
        "links": uniq,
        "vlan_colors": sorted(vlan_color_seed.keys()),
    }
