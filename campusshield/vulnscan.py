"""Weakness detection: risky exposed services, banner-based outdated-software signatures
and zone-policy violations. This is a lightweight heuristic engine - confirm important
findings with a full scanner such as OpenVAS/Greenbone or Nessus."""
import re

from . import config

# port -> (service, CVSS-like severity, title, remediation)
RISKY_PORTS = {
    21: ("FTP", 7.5, "Cleartext FTP service exposed", "Replace with SFTP/FTPS or disable the service."),
    23: ("Telnet", 9.1, "Telnet (cleartext remote login) exposed", "Disable Telnet; use SSH with key/strong auth."),
    139: ("NetBIOS", 6.5, "NetBIOS session service exposed", "Disable NetBIOS over TCP/IP if not required."),
    445: ("SMB", 8.1, "SMB file sharing exposed", "Restrict SMB to required hosts; disable SMBv1; patch regularly."),
    1433: ("MSSQL", 7.5, "Microsoft SQL Server port exposed", "Allow only application servers; enforce strong auth."),
    3306: ("MySQL", 7.5, "MySQL database port exposed", "Bind to localhost/app VLAN; firewall from user networks."),
    3389: ("RDP", 7.8, "Remote Desktop (RDP) exposed", "Restrict RDP behind VPN/jump host; enable NLA and MFA."),
    5432: ("PostgreSQL", 7.5, "PostgreSQL port exposed", "Restrict to application servers via pg_hba.conf and firewall."),
    5900: ("VNC", 8.0, "VNC remote desktop exposed", "Disable or tunnel over SSH/VPN; require strong password."),
    6379: ("Redis", 9.0, "Redis exposed (often unauthenticated)", "Bind to localhost, set requirepass, firewall the port."),
    9100: ("JetDirect", 5.0, "Raw printer port reachable", "Limit printing to the print server; isolate printers."),
    27017: ("MongoDB", 9.0, "MongoDB port exposed", "Enable authentication and restrict network access."),
}

# regex on banner -> (title, CVSS-like severity, remediation)
BANNER_SIGNATURES = [
    (r"vsFTPd 2\.3\.4", "vsFTPd 2.3.4 backdoor (CVE-2011-2523)", 9.8, "Upgrade vsFTPd immediately."),
    (r"OpenSSH[_ ]([0-6])\.", "Outdated OpenSSH (< 7.0) with known CVEs", 7.5, "Upgrade OpenSSH to a supported release."),
    (r"Apache/2\.2\.", "End-of-life Apache 2.2 web server", 7.5, "Upgrade to a supported Apache 2.4 release."),
    (r"Microsoft-IIS/[56]\.", "End-of-life IIS 5/6 (e.g. CVE-2017-7269)", 9.8, "Migrate to a supported Windows Server/IIS."),
    (r"nginx/1\.(0|2|4|6)\.", "Outdated nginx release", 6.5, "Upgrade nginx to a supported version."),
    (r"lighttpd/1\.[0-3]\.", "Outdated lighttpd release", 6.5, "Upgrade lighttpd."),
]

USER_ZONE_SERVER_PORTS = (22, 80, 443, 8080, 8443)


def assess(asset: dict):
    """Return a list of finding dicts (without risk score) for one asset."""
    ports = asset["open_ports"]
    zone = config.zone_for_ip(asset["ip"])
    out = []

    for port, info in ports.items():
        if port in RISKY_PORTS:
            svc, cvss, title, fix = RISKY_PORTS[port]
            out.append({"fkey": f"port{port}", "type": "risky_port", "title": title, "port": port,
                        "cvss": cvss, "detail": f"{svc} open on port {port}. Remediation: {fix}"})
        banner = info.get("banner", "") or ""
        for pat, title, cvss, fix in BANNER_SIGNATURES:
            if re.search(pat, banner, re.I):
                out.append({"fkey": f"banner{port}", "type": "outdated_software", "title": title, "port": port,
                            "cvss": cvss, "detail": f"Banner on port {port}: '{banner[:80]}'. Remediation: {fix}"})
                break

    if 80 in ports and 443 not in ports and asset.get("device_type") != "Printer":
        out.append({"fkey": "cleartext80", "type": "cleartext_web", "title": "Web service without HTTPS", "port": 80,
                    "cvss": 5.3, "detail": "HTTP served without HTTPS. Remediation: enable TLS and redirect HTTP."})

    if zone["profile"] == "restricted" and zone["trust"] in ("low", "untrusted"):
        for p in USER_ZONE_SERVER_PORTS:
            if p in ports:
                out.append({"fkey": f"svc{p}", "type": "policy", "title": f"Server service ({ports[p]['service']}) running in {zone['name']} VLAN",
                            "port": p, "cvss": 4.3,
                            "detail": "User VLANs should not host servers. Remediation: move to the server VLAN or disable the service."})
    return out
