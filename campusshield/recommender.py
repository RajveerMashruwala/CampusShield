"""Policy / recommendation engine: turns findings into concrete, reviewable controls
(Cisco IOS ACL entries) and generates baseline zone ACLs from the access-policy matrix."""
import ipaddress
import re

from . import config, risk, vulnscan


def _wild(net: ipaddress.IPv4Network) -> str:
    return str(net.hostmask)


class SeqAllocator:
    """Hands out unused ACL sequence numbers (10-99) so new entries sit above the
    existing rules after 'ip access-list resequence <name> 100 10'."""

    def __init__(self, existing_configs=()):
        self.used = {}
        for text in existing_configs:
            cur = None
            for line in text.splitlines():
                m = re.match(r"ip access-list extended (\S+)", line.strip())
                if m:
                    cur = m.group(1); continue
                m = re.match(r"\s+(\d+)\s+(permit|deny)", line)
                if m and cur:
                    self.used.setdefault(cur, set()).add(int(m.group(1)))

    def next(self, acl):
        used = self.used.setdefault(acl, set())
        for n in range(10, 100):
            if n not in used:
                used.add(n)
                return n
        raise RuntimeError(f"No free sequence numbers left in {acl}")


def _acl_block_config(asset, port, alloc):
    zone = config.zone_for_ip(asset["ip"])
    chunks = []
    for src in config.load_zones():
        if src["vlan"] == zone["vlan"] or src["trust"] not in config.UNTRUSTED_SOURCE_TRUST or not src.get("acl"):
            continue
        net = ipaddress.ip_network(src["subnet"])
        seq = alloc.next(src["acl"])
        chunks.append(f"ip access-list resequence {src['acl']} 100 10\n"
                      f"ip access-list extended {src['acl']}\n"
                      f" {seq} deny tcp {net.network_address} {_wild(net)} host {asset['ip']} eq {port} log")
    return "\n!\n".join(chunks)


def recommend(asset, finding, alloc):
    """One recommendation dict for one finding (or None)."""
    zone = config.zone_for_ip(asset["ip"])
    key = f"{asset['ip']}:{finding['fkey']}"
    base = {"key": key, "asset_ip": asset["ip"], "risk_score": finding["risk_score"], "priority": finding["priority"]}
    remedy = finding["detail"].split("Remediation:")[-1].strip()
    if finding["type"] == "risky_port" and zone["trust"] not in ("low", "untrusted"):
        cfg = _acl_block_config(asset, finding["port"], alloc)
        if cfg:
            return {**base, "title": f"Block {vulnscan.RISKY_PORTS[finding['port']][0]} (tcp/{finding['port']}) to {asset['ip']} from user zones",
                    "control_type": "acl_block", "enforceable": True, "config_text": cfg,
                    "description": f"Deny access to tcp/{finding['port']} on {asset['ip']} from low/untrusted/medium-trust VLANs. "
                                   f"Also: {remedy}"}
    ctype = "patch" if finding["type"] == "outdated_software" else "harden"
    return {**base, "title": f"{finding['title']} on {asset['ip']}", "control_type": ctype, "enforceable": False,
            "config_text": "", "description": f"Manual action required. {remedy}"}


def quarantine(asset, total_risk, alloc):
    zone = config.zone_for_ip(asset["ip"])
    if not zone.get("quarantinable") or not zone.get("acl"):
        return None
    seq = alloc.next(zone["acl"])
    cfg = (f"ip access-list resequence {zone['acl']} 100 10\n"
           f"ip access-list extended {zone['acl']}\n {seq} deny ip host {asset['ip']} any log")
    return {"key": f"{asset['ip']}:quarantine", "asset_ip": asset["ip"], "risk_score": total_risk,
            "priority": risk.priority(total_risk), "title": f"Quarantine {asset['ip']} ({asset.get('device_type','host')}) - critical risk",
            "control_type": "quarantine", "enforceable": True, "config_text": cfg,
            "description": "Block all traffic from this host at its VLAN gateway until it is remediated."}


# ---- baseline zone ACLs ----------------------------------------------------
def baseline_acl(zone):
    net = ipaddress.ip_network(zone["subnet"])
    src, w = net.network_address, _wild(net)
    dns, lms = config.SERVICES["dns"], config.SERVICES["lms"]
    sup = config.CAMPUS_SUPERNET
    L = [f"ip access-list extended {zone['acl']}", " remark Allow DHCP", " permit udp any eq 68 any eq 67"]
    p = zone["profile"]
    if p in ("restricted", "iot", "staff"):
        L += [" remark DNS", f" permit udp {src} {w} host {dns} eq 53", f" permit tcp {src} {w} host {dns} eq 53"]
    if p in ("restricted", "staff"):
        L += [" remark LMS portal", f" permit tcp {src} {w} host {lms} eq 443"]
    if p == "staff":
        srv = ipaddress.ip_network(config.load_zones()[4]["subnet"])
        L += [" remark Staff/Faculty may use the server VLAN", f" permit ip {src} {w} {srv.network_address} {_wild(srv)}",
              " remark Block management VLAN", f" deny ip {src} {w} 10.10.99.0 0.0.0.255 log"]
    if p in ("restricted", "iot"):
        L += [" remark Block all internal networks", f" deny ip {src} {w} {sup.network_address} {sup.hostmask} log"]
    if p == "restricted":
        L += [" remark Internet web", f" permit tcp {src} {w} any eq 80", f" permit tcp {src} {w} any eq 443"]
    if p == "staff":
        L += [f" permit tcp {src} {w} any eq 80", f" permit tcp {src} {w} any eq 443"]
    if p == "iot":
        L += [f" permit tcp {src} {w} any eq 443", f" permit udp {src} {w} any eq 123"]
    if p == "server":
        L += [f" permit ip {src} {w} {src} {w}", f" permit udp {src} {w} any eq 53", f" permit udp {src} {w} any eq 123",
              f" permit tcp {src} {w} any eq 80", f" permit tcp {src} {w} any eq 443"]
    if p == "mgmt":
        L += [f" permit ip {src} {w} any"]
    L += [" remark Explicit deny with logging", " deny ip any any log", "!",
          f"interface Vlan{zone['vlan']}", f" ip access-group {zone['acl']} in"]
    return "\n".join(L)


def baseline_configs():
    return {z["name"]: baseline_acl(z) for z in config.load_zones() if z.get("acl")}
