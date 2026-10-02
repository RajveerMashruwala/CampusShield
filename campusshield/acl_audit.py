"""Cisco IOS extended-ACL parser and auditor.

Detects: permit-any-any, overly broad permits, shadowed/redundant rules, risky ports permitted,
missing final 'deny ip any any log', user ACLs that expose the internal network, ACLs that are
defined but never applied, and VLAN interfaces without an inbound ACL.
"""
import ipaddress
import re
from dataclasses import dataclass

from . import config

PORT_NAMES = {"www": 80, "domain": 53, "telnet": 23, "ssh": 22, "smtp": 25, "ftp": 21, "ftp-data": 20,
              "https": 443, "bootps": 67, "bootpc": 68, "snmp": 161, "ntp": 123, "pop3": 110, "imap": 143,
              "tftp": 69, "syslog": 514, "sunrpc": 111, "msrpc": 135}
ANY = ipaddress.ip_network("0.0.0.0/0")
FULL = (0, 65535)
RISKY_PERMIT_PORTS = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
                      3306: "MySQL", 3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"}
RESTRICTED_NAME = re.compile(r"STUDENT|GUEST|IOT|LAB", re.I)


@dataclass
class Rule:
    acl: str
    line_no: int
    seq: int
    action: str
    proto: str
    src: ipaddress.IPv4Network
    sport: tuple
    dst: ipaddress.IPv4Network
    dport: tuple
    log: bool
    established: bool
    raw: str


def _port(tok):
    return int(tok) if tok.isdigit() else PORT_NAMES[tok.lower()]


def _addr(tokens, i):
    t = tokens[i]
    if t == "any":
        return ANY, i + 1
    if t == "host":
        return ipaddress.ip_network(tokens[i + 1] + "/32"), i + 2
    base = ipaddress.ip_address(t)
    if i + 1 < len(tokens):
        try:
            wild = ipaddress.ip_address(tokens[i + 1])
            mask = ipaddress.ip_address(int(wild) ^ 0xFFFFFFFF)
            return ipaddress.ip_network(f"{base}/{mask}", strict=False), i + 2
        except ValueError:
            pass
    return ipaddress.ip_network(f"{base}/32"), i + 1


def _ports(tokens, i):
    if i < len(tokens) and tokens[i] in ("eq", "gt", "lt", "range"):
        op = tokens[i]
        if op == "eq":
            p = _port(tokens[i + 1]); return (p, p), i + 2
        if op == "gt":
            return (_port(tokens[i + 1]) + 1, 65535), i + 2
        if op == "lt":
            return (0, _port(tokens[i + 1]) - 1), i + 2
        return (_port(tokens[i + 1]), _port(tokens[i + 2])), i + 3
    return FULL, i


def parse_rule(acl, line_no, line):
    t = line.split()
    seq = 0
    if t and t[0].isdigit():
        seq, t = int(t[0]), t[1:]
    if len(t) < 3 or t[0] not in ("permit", "deny"):
        return None
    action, proto, i = t[0], t[1].lower(), 2
    src, i = _addr(t, i)
    sport, i = _ports(t, i) if proto in ("tcp", "udp") else (FULL, i)
    dst, i = _addr(t, i)
    dport, i = _ports(t, i) if proto in ("tcp", "udp") else (FULL, i)
    rest = t[i:]
    return Rule(acl, line_no, seq, action, proto, src, sport, dst, dport, "log" in rest,
                "established" in rest, line.strip())


def parse_config(text):
    """Return (acls: {name: [Rule]}, interfaces: {name: {'acl_in': str|None}}, warnings)."""
    acls, ifaces, warnings = {}, {}, []
    mode = None
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        if s == "!":
            mode = None
            continue
        if not line[0].isspace():
            m = re.match(r"ip access-list extended (\S+)", s)
            if m:
                mode = ("acl", m.group(1)); acls.setdefault(m.group(1), []); continue
            m = re.match(r"interface (\S+)", s, re.I)
            if m:
                mode = ("if", m.group(1)); ifaces[m.group(1)] = {"acl_in": None}; continue
            mode = None
            continue
        if not mode:
            continue
        if mode[0] == "acl" and not s.startswith("remark"):
            try:
                r = parse_rule(mode[1], n, s)
                if r:
                    acls[mode[1]].append(r)
            except Exception as e:  # unparsable line: keep going, report it
                warnings.append(f"line {n}: could not parse '{s}' ({e})")
        elif mode[0] == "if":
            m = re.match(r"ip access-group (\S+) in", s)
            if m:
                ifaces[mode[1]]["acl_in"] = m.group(1)
    for rules in acls.values():
        if any(r.seq for r in rules):
            rules.sort(key=lambda r: r.seq or 10**9)
    return acls, ifaces, warnings


def covers(a: Rule, b: Rule) -> bool:
    """True if every packet matching b also matches a (a is earlier)."""
    if a.proto != "ip" and a.proto != b.proto:
        return False
    if a.established and not b.established:
        return False
    return (b.src.subnet_of(a.src) and b.dst.subnet_of(a.dst)
            and a.sport[0] <= b.sport[0] and b.sport[1] <= a.sport[1]
            and a.dport[0] <= b.dport[0] and b.dport[1] <= a.dport[1])


def _issue(acl, rule, severity, issue, detail, fix):
    return {"acl": acl, "line_no": rule.line_no if rule else None, "severity": severity, "issue": issue,
            "detail": detail, "fix": fix}


def audit_acl(name, rules):
    out = []
    supernet = config.CAMPUS_SUPERNET
    internal_blocked = False
    for j, r in enumerate(rules):
        if r.action == "permit" and r.proto == "ip" and r.src == ANY and r.dst == ANY:
            out.append(_issue(name, r, "critical", "permit ip any any",
                              f"Rule '{r.raw}' allows all traffic and defeats the ACL.",
                              "Replace with service-specific permits followed by 'deny ip any any log'."))
        elif (r.action == "permit" and r.src == ANY and r.dst == ANY
              and not (r.proto == "udp" and r.dport == (67, 67))):
            out.append(_issue(name, r, "high", "Overly broad permit",
                              f"Rule '{r.raw}' permits {r.proto} from any to any.",
                              "Restrict source/destination to required subnets and hosts."))
        if r.action == "permit" and r.dport[0] == r.dport[1] and r.dport[0] in RISKY_PERMIT_PORTS:
            svc = RISKY_PERMIT_PORTS[r.dport[0]]
            out.append(_issue(name, r, "critical" if r.dport[0] == 23 else "high", f"Risky service permitted: {svc}",
                              f"Rule '{r.raw}' allows {svc} (port {r.dport[0]}).",
                              f"Remove the rule or limit {svc} to specific management hosts."))
        for i in range(j):
            if covers(rules[i], r):
                same = rules[i].action == r.action
                out.append(_issue(name, r, "medium" if same else "high",
                                  "Redundant rule" if same else "Shadowed rule (never matches)",
                                  f"Rule '{r.raw}' is already covered by earlier line {rules[i].line_no} "
                                  f"('{rules[i].raw}').",
                                  "Remove the rule or move it above the broader rule."))
                break
        if r.action == "deny" and r.proto == "ip" and supernet.subnet_of(r.dst):
            internal_blocked = True
        approved_host = r.dst.prefixlen == 32 and str(r.dst.network_address) in config.SERVICES.values()
        is_dhcp = r.proto == "udp" and r.dport == (67, 67)
        if (r.action == "permit" and RESTRICTED_NAME.search(name) and not internal_blocked
                and r.dst.overlaps(supernet) and not approved_host and not is_dhcp):
            out.append(_issue(name, r, "high", "Restricted zone can reach internal network",
                              f"Rule '{r.raw}' is evaluated before any deny to {supernet}, so users may reach "
                              "internal servers/VLANs.",
                              f"Insert 'deny ip <zone-subnet> {supernet.network_address} "
                              f"{supernet.hostmask} log' before internet permits."))
    last = rules[-1] if rules else None
    if last is None or not (last.action == "deny" and last.proto == "ip" and last.src == ANY and last.dst == ANY):
        out.append(_issue(name, last, "medium", "Missing final 'deny ip any any log'",
                          "ACL does not end with an explicit logged deny, so denied traffic is not recorded.",
                          "Append 'deny ip any any log'."))
    elif not last.log:
        out.append(_issue(name, last, "low", "Final deny is not logged", "Denied traffic is not logged.",
                          "Add the 'log' keyword to the final deny."))
    return out


def audit_config(text):
    acls, ifaces, warnings = parse_config(text)
    issues = []
    for name, rules in acls.items():
        issues += audit_acl(name, rules)
    applied = {v["acl_in"] for v in ifaces.values() if v["acl_in"]}
    for name in acls:
        if name not in applied:
            issues.append({"acl": name, "line_no": None, "severity": "medium", "issue": "ACL defined but not applied",
                           "detail": f"ACL {name} is not bound to any interface.",
                           "fix": "Apply it with 'ip access-group %s in' on the matching VLAN interface." % name})
    for iface, v in ifaces.items():
        m = re.match(r"vlan(\d+)", iface, re.I)
        if m and not v["acl_in"]:
            issues.append({"acl": iface, "line_no": None, "severity": "high", "issue": "VLAN interface has no inbound ACL",
                           "detail": f"{iface} routes traffic with no inbound filtering.",
                           "fix": f"Create and apply a zone ACL (see Baseline ACLs page) on {iface}."})
    for w in warnings:
        issues.append({"acl": "parser", "line_no": None, "severity": "low", "issue": "Unparsed line", "detail": w,
                       "fix": "Review manually."})
    return issues, acls
