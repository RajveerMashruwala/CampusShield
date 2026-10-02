"""Deterministic simulated campus used by `run.py demo` (no real network access needed)."""
import shutil

from . import config, db, discovery

P = discovery.SERVICE_NAMES

# (ip, hostname, mac, {port: banner})
DEMO_HOSTS = [
    ("10.10.10.11", "admin-pc-01", "3c:d9:2b:11:22:01", {445: "", 3389: ""}),
    ("10.10.10.12", "accounts-pc", "00:21:5a:11:22:02", {445: ""}),
    ("10.10.20.21", "faculty-lap-07", "a4:5e:60:aa:bb:07", {22: "SSH-2.0-OpenSSH_8.9"}),
    ("10.10.30.101", "student-lap-101", "00:1b:63:01:01:65", {445: "", 3389: ""}),
    ("10.10.30.102", "student-lap-102", "a4:5e:60:01:01:66", {}),
    ("10.10.30.140", "rogue-pi", "b8:27:eb:12:34:56", {22: "SSH-2.0-OpenSSH_5.3", 80: "Apache/2.2.15 (CentOS)"}),
    ("10.10.40.11", "lab1-pc-01", "d8:cb:8a:40:00:01", {3389: "", 445: ""}),
    ("10.10.40.12", "lab1-pc-02", "d8:cb:8a:40:00:02", {3389: ""}),
    ("10.10.50.10", "dns-01", "00:50:56:50:00:10", {22: "SSH-2.0-OpenSSH_8.9", 53: ""}),
    ("10.10.50.20", "lms-web-01", "00:50:56:50:00:20", {22: "SSH-2.0-OpenSSH_6.6", 80: "Apache/2.2.15 (CentOS)", 443: "", 3306: ""}),
    ("10.10.50.30", "fileserver-01", "00:50:56:50:00:30", {445: "", 139: "", 3389: ""}),
    ("10.10.50.40", "ftp-legacy", "00:50:56:50:00:40", {21: "220 (vsFTPd 2.3.4)"}),
    ("10.10.50.50", "cache-redis", "00:50:56:50:00:50", {6379: ""}),
    ("10.10.60.15", "guest-device-15", "f4:f5:d8:60:00:15", {}),
    ("10.10.70.5", "hall-printer", "00:80:77:70:00:05", {80: "", 9100: "", 21: "220 Printer FTP"}),
    ("10.10.70.31", "cctv-gate", "44:19:b6:70:00:31", {23: "login:", 80: "lighttpd/1.2.2", 554: ""}),
    ("10.10.70.32", "cctv-library", "00:1f:a4:70:00:32", {23: "login:", 554: ""}),
    ("10.10.99.2", "core-sw1", "00:1a:2b:99:00:02", {22: "SSH-2.0-Cisco-1.25", 23: "User Access Verification"}),
]


def load_demo(reset=True):
    if reset:
        db.reset()
    for ip, host, mac, ports in DEMO_HOSTS:
        plist = {p: {"service": P.get(p, "unknown"), "banner": b} for p, b in ports.items()}
        db.upsert_asset(discovery.build_asset(ip, plist, mac, host))
    src = config.BASE_DIR / "sample_configs" / "running-config-insecure.txt"
    config.data_dir().mkdir(parents=True, exist_ok=True)
    shutil.copy(src, config.running_config_path())
    db.log("system", "demo-load", f"{len(DEMO_HOSTS)} simulated assets + insecure sample config loaded")
