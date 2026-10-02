"""Risk model:  Risk = CVSS x Asset Criticality (1-5) x Exposure Factor (zone based)."""
from . import config


def score(cvss: float, criticality: int, exposure: float) -> float:
    return round(float(cvss) * int(criticality) * float(exposure), 1)


def priority(value: float) -> str:
    if value > 40:
        return "critical"
    if value >= 20:
        return "high"
    if value >= 8:
        return "medium"
    return "low"


def exposure_for(ip: str) -> float:
    return float(config.zone_for_ip(ip)["exposure"])
