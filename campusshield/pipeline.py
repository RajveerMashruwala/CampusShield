"""Orchestrates the CampusShield cycle: Discover -> Assess -> Recommend -> (approve) -> Enforce."""
from collections import defaultdict

from . import acl_audit, config, db, recommender, risk, vulnscan


def run_acl_audit():
    path = config.running_config_path()
    text = path.read_text() if path.exists() else ""
    issues, _ = acl_audit.audit_config(text) if text else ([], {})
    db.replace_acl_issues(issues)
    return issues


def run_analysis():
    """Re-assess every stored asset, rescore, regenerate recommendations and re-audit ACLs."""
    assets = db.assets()
    applied = {r["key"] for r in db.recs(status="applied")}
    all_findings, per_asset_open = [], defaultdict(list)
    for a in assets:
        exposure = risk.exposure_for(a["ip"])
        for f in vulnscan.assess(a):
            f["asset_ip"] = a["ip"]
            f["risk_score"] = risk.score(f["cvss"], a["criticality"], exposure)
            f["priority"] = risk.priority(f["risk_score"])
            mitigated = f"{a['ip']}:{f['fkey']}" in applied or f"{a['ip']}:quarantine" in applied
            f["status"] = "mitigated" if mitigated else "open"
            all_findings.append(f)
            if not mitigated:
                per_asset_open[a["ip"]].append(f)
    db.replace_findings(all_findings)

    alloc = recommender.SeqAllocator(r["config_text"] for r in db.recs() if r["config_text"])
    by_ip = {a["ip"]: a for a in assets}
    new_recs = []
    for ip, fs in per_asset_open.items():
        a = by_ip[ip]
        for f in sorted(fs, key=lambda x: -x["risk_score"]):
            r = recommender.recommend(a, f, alloc)
            if r:
                new_recs.append(r)
        top = max(f["risk_score"] for f in fs)
        if top > 40:
            q = recommender.quarantine(a, top, alloc)
            if q:
                new_recs.append(q)
    db.replace_recs(new_recs)
    run_acl_audit()
    return {"assets": len(assets), "findings": len(all_findings), "recommendations": len(new_recs)}


def summary():
    assets = db.assets()
    findings = db.findings()
    open_f = [f for f in findings if f["status"] == "open"]
    asset_risk = defaultdict(float)
    for f in open_f:
        asset_risk[f["asset_ip"]] = max(asset_risk[f["asset_ip"]], f["risk_score"])
    by_ip = {a["ip"]: a for a in assets}
    zone_risk = defaultdict(float)
    for ip, v in asset_risk.items():
        zone_risk[by_ip[ip]["zone"]] += v
    prios = {p: sum(1 for f in open_f if f["priority"] == p) for p in ("critical", "high", "medium", "low")}
    top = sorted(asset_risk.items(), key=lambda kv: -kv[1])[:8]
    issues = db.acl_issues()
    return {
        "assets": len(assets),
        "open_findings": len(open_f),
        "mitigated": len(findings) - len(open_f),
        "priorities": prios,
        "aggregate_risk": round(sum(asset_risk.values()), 1),
        "zone_risk": sorted(((z, round(v, 1)) for z, v in zone_risk.items()), key=lambda kv: -kv[1]),
        "top_assets": [{"ip": ip, "risk": v, "priority": risk.priority(v), "hostname": by_ip[ip]["hostname"],
                        "zone": by_ip[ip]["zone"]} for ip, v in top],
        "pending_recs": len(db.recs(status="pending")),
        "acl_issues": len(issues),
        "acl_critical": sum(1 for i in issues if i["severity"] == "critical"),
    }
