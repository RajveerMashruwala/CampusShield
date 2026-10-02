"""Asset discovery: TCP connect scan (pure Python), ARP-table lookup and optional Nmap.

Safety: by default only private (RFC1918/loopback) targets of at most 1024 addresses are
allowed. Only scan networks you own or are authorised in writing to test.
"""
import ipaddress
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from . import config

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 1433, 3306, 3389,
                5432, 5900, 6379, 8080, 8443, 9100, 27017]

SERVICE_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
                 139: "netbios", 143: "imap", 443: "https", 445: "smb", 554: "rtsp", 1433: "mssql",
                 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
                 8080: "http-alt", 8443: "https-alt", 9100: "jetdirect", 27017: "mongodb"}

OUI = {"00:50:56": "VMware", "08:00:27": "VirtualBox", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
       "00:0c:29": "VMware", "3c:5a:b4": "Google", "f4:f5:d8": "Google", "00:1b:63": "Apple",
       "a4:5e:60": "Apple", "00:1a:2b": "Cisco", "00:1e:13": "Cisco", "00:17:88": "Philips",
       "00:1f:a4": "Hikvision", "44:19:b6": "Hikvision", "00:80:77": "Brother", "00:00:48": "Epson",
       "3c:d9:2b": "HP", "00:21:5a": "HP", "00:25:b3": "HP", "d8:cb:8a": "Micro-Star (MSI)"}


def vendor_from_mac(mac):
    return OUI.get((mac or "").lower()[:8], "Unknown")


def validate_target(target: str, allow_public: bool = False, max_hosts: int = 1024):
    net = ipaddress.ip_network(target, strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 targets are supported in this prototype.")
    if not allow_public and not net.is_private:
        raise ValueError("Refusing to scan a non-private network. Use --allow-public only if you are authorised.")
    if net.num_addresses > max_hosts:
        raise ValueError(f"Target too large ({net.num_addresses} addresses, max {max_hosts}).")
    return net


def arp_table():
    """IP -> MAC from the local neighbour table (Linux 'ip neigh' / 'arp -an'). Best effort."""
    table = {}
    for cmd in (["ip", "neigh"], ["arp", "-an"]):
        if not shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except Exception:
            continue
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                table[m.group(1)] = m.group(2).lower()
        if table:
            break
    return table


def _banner(ip, port, timeout):
    """Read a short service banner (never sends payloads other than a plain HEAD request)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8443, 443):
                if port in (443, 8443):
                    return ""
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                data = s.recv(512).decode(errors="ignore")
                m = re.search(r"(?im)^server:\s*(.+)$", data)
                return m.group(1).strip() if m else ""
            if port in (21, 22, 23, 25, 110, 143):
                lines = s.recv(256).decode(errors="ignore").strip().splitlines()
                return lines[0][:120] if lines else ""
    except Exception:
        return ""
    return ""


def _probe_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except Exception:
        return None


def scan_host(ip, ports=None, timeout=0.6):
    ports = ports or COMMON_PORTS
    found = {}
    for p in ports:
        if _probe_port(ip, p, timeout):
            found[p] = {"service": SERVICE_NAMES.get(p, "unknown"), "banner": _banner(ip, p, timeout)}
    return found


def nmap_available():
    return shutil.which("nmap") is not None


def nmap_scan(target, ports=None):
    """Run nmap (-sT -sV) and parse its XML. Returns {ip: {'mac', 'hostname', 'ports'}}."""
    ports = ports or COMMON_PORTS
    cmd = ["nmap", "-sT", "-sV", "--open", "-T4", "-p", ",".join(map(str, ports)), "-oX", "-", target]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=900).stdout
    root = ET.fromstring(out)
    hosts = {}
    for h in root.findall("host"):
        ip = mac = name = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr").lower()
        hn = h.find("hostnames/hostname")
        name = hn.get("name") if hn is not None else None
        pmap = {}
        for p in h.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            banner = " ".join(filter(None, [svc.get("product") if svc is not None else "",
                                            svc.get("version") if svc is not None else ""])).strip()
            pmap[int(p.get("portid"))] = {"service": svc.get("name") if svc is not None else "unknown",
                                          "banner": banner}
        if ip:
            hosts[ip] = {"mac": mac, "hostname": name, "ports": pmap}
    return hosts


def guess_os_and_type(ports: dict):
    banners = " ".join(v.get("banner", "") for v in ports.values()).lower()
    if "microsoft" in banners or 445 in ports or 3389 in ports or 139 in ports:
        osn = "Windows (guess)"
    elif "openssh" in banners or "apache" in banners or "nginx" in banners or 22 in ports:
        osn = "Linux/Unix (guess)"
    else:
        osn = "Unknown"
    if 9100 in ports:
        dtype = "Printer"
    elif 554 in ports:
        dtype = "IP Camera"
    elif any(p in ports for p in (3306, 5432, 1433, 27017, 6379)):
        dtype = "Database server"
    elif 80 in ports or 443 in ports:
        dtype = "Web server" if 22 in ports else "Web device"
    elif 3389 in ports or 445 in ports:
        dtype = "Workstation"
    else:
        dtype = "Host"
    return osn, dtype


def build_asset(ip, ports, mac=None, hostname=None):
    zone = config.zone_for_ip(ip)
    osn, dtype = guess_os_and_type(ports)
    crit = zone["criticality"]
    if any(p in ports for p in (3306, 5432, 1433, 27017, 6379)):
        crit = 5
    return {"ip": ip, "mac": mac, "hostname": hostname or "", "vendor": vendor_from_mac(mac), "os": osn,
            "device_type": dtype, "vlan": zone["vlan"], "zone": zone["name"], "criticality": crit,
            "open_ports": ports}


def scan_network(target, ports=None, use_nmap=False, allow_public=False, workers=64, progress=None):
    """Discover assets in `target` (CIDR). Returns a list of asset dicts (not yet stored)."""
    net = validate_target(target, allow_public)
    arp = {}
    results = {}
    if use_nmap:
        if not nmap_available():
            raise RuntimeError("nmap not found on PATH; run without --nmap to use the built-in scanner.")
        results = {ip: (h["ports"], h["mac"], h["hostname"]) for ip, h in nmap_scan(target, ports).items()}
    else:
        hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for i, (ip, found) in enumerate(zip(hosts, ex.map(lambda h: scan_host(h, ports), hosts))):
                if found:
                    results[ip] = (found, None, "")
                if progress:
                    progress(i + 1, len(hosts))
    arp = arp_table()
    return [build_asset(ip, p, mac or arp.get(ip), name) for ip, (p, mac, name) in sorted(results.items())]
