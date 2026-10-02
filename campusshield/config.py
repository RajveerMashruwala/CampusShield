"""Central configuration: paths, campus zone model (VLANs) and policy constants."""
import ipaddress
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Campus supernet used for "internal vs internet" decisions.
CAMPUS_SUPERNET = ipaddress.ip_network("10.10.0.0/16")

# Well-known campus services referenced by the generated ACLs.
SERVICES = {"dns": "10.10.50.10", "lms": "10.10.50.20"}

# Zone model. Each zone = one VLAN. 'exposure' is the exposure factor used in the
# risk formula (how reachable the zone is from untrusted users); 'criticality' is the
# default asset criticality (1-5); 'profile' selects the baseline ACL template.
DEFAULT_ZONES = [
    {"vlan": 10, "name": "Administration / Staff", "subnet": "10.10.10.0/24", "trust": "high",
     "criticality": 4, "exposure": 0.8, "acl": "STAFF-IN", "profile": "staff", "quarantinable": False},
    {"vlan": 20, "name": "Faculty", "subnet": "10.10.20.0/24", "trust": "high",
     "criticality": 3, "exposure": 0.8, "acl": "FACULTY-IN", "profile": "staff", "quarantinable": False},
    {"vlan": 30, "name": "Students", "subnet": "10.10.30.0/24", "trust": "low",
     "criticality": 1, "exposure": 1.2, "acl": "STUDENT-IN", "profile": "restricted", "quarantinable": True},
    {"vlan": 40, "name": "Computer Labs", "subnet": "10.10.40.0/24", "trust": "medium",
     "criticality": 2, "exposure": 1.0, "acl": "LAB-IN", "profile": "restricted", "quarantinable": True},
    {"vlan": 50, "name": "Servers / DMZ", "subnet": "10.10.50.0/24", "trust": "critical",
     "criticality": 5, "exposure": 1.5, "acl": "SERVER-IN", "profile": "server", "quarantinable": False},
    {"vlan": 60, "name": "Guest Wi-Fi", "subnet": "10.10.60.0/24", "trust": "untrusted",
     "criticality": 1, "exposure": 1.5, "acl": "GUEST-IN", "profile": "restricted", "quarantinable": True},
    {"vlan": 70, "name": "IoT / CCTV / Printers", "subnet": "10.10.70.0/24", "trust": "low",
     "criticality": 2, "exposure": 1.3, "acl": "IOT-IN", "profile": "iot", "quarantinable": True},
    {"vlan": 99, "name": "Management", "subnet": "10.10.99.0/24", "trust": "critical",
     "criticality": 5, "exposure": 1.0, "acl": "MGMT-IN", "profile": "mgmt", "quarantinable": False},
]

UNKNOWN_ZONE = {"vlan": None, "name": "Unknown", "subnet": None, "trust": "medium", "criticality": 2,
                "exposure": 1.0, "acl": None, "profile": "restricted", "quarantinable": False}

UNTRUSTED_SOURCE_TRUST = ("low", "untrusted", "medium")


def data_dir() -> Path:
    return Path(os.environ.get("CAMPUSSHIELD_DATA", BASE_DIR / "data"))


def db_path() -> Path:
    return data_dir() / "campusshield.db"


def running_config_path() -> Path:
    """Path of the (simulated) device running-config the audit/enforcement work on."""
    return data_dir() / "running-config.txt"


def backup_dir() -> Path:
    return data_dir() / "backups"


def output_dir() -> Path:
    return data_dir() / "output"


def load_zones():
    """Zones from $CAMPUSSHIELD_ZONES (JSON file) if set, else the defaults."""
    p = os.environ.get("CAMPUSSHIELD_ZONES")
    if p and Path(p).exists():
        return json.loads(Path(p).read_text())
    return DEFAULT_ZONES


def zone_for_ip(ip: str) -> dict:
    addr = ipaddress.ip_address(ip)
    for z in load_zones():
        if z.get("subnet") and addr in ipaddress.ip_network(z["subnet"]):
            return z
    return UNKNOWN_ZONE


def zone_by_name(name: str):
    for z in load_zones():
        if z["name"] == name:
            return z
    return None
