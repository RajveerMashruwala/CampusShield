#!/usr/bin/env python3
"""CampusShield command line interface.

  python run.py demo [--serve]           load simulated campus, analyse, print report
  python run.py scan --target 10.10.30.0/24 [--nmap]
  python run.py audit --file running-config.txt
  python run.py baseline                 print baseline zone ACLs
  python run.py serve [--host H --port P]
"""
import argparse
import sys

from campusshield import acl_audit, config, db, demo_data, discovery, pipeline, recommender


def print_report():
    s = pipeline.summary()
    print("\n=== CampusShield summary ===")
    print(f"Assets: {s['assets']} | Open findings: {s['open_findings']} | Aggregate risk: {s['aggregate_risk']}")
    print("Priorities:", ", ".join(f"{k}={v}" for k, v in s["priorities"].items()))
    print(f"ACL issues: {s['acl_issues']} ({s['acl_critical']} critical) | Pending recommendations: {s['pending_recs']}")
    print("\nTop risky assets:")
    for a in s["top_assets"]:
        print(f"  {a['ip']:<14} {a['hostname']:<16} {a['zone']:<24} risk={a['risk']:<6} [{a['priority']}]")
    print("\nTop recommendations:")
    for r in db.recs(status="pending")[:6]:
        print(f"  #{r['id']:<3} [{r['priority']:<8}] {r['title']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="CampusShield - Smart Campus Network Security")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--serve", action="store_true")
    sc = sub.add_parser("scan"); sc.add_argument("--target", required=True)
    sc.add_argument("--nmap", action="store_true"); sc.add_argument("--allow-public", action="store_true")
    sc.add_argument("--ports", help="comma separated, default = common campus ports")
    au = sub.add_parser("audit"); au.add_argument("--file", required=True)
    sub.add_parser("baseline")
    sv = sub.add_parser("serve"); sv.add_argument("--host", default="127.0.0.1"); sv.add_argument("--port", type=int, default=5000)
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        demo_data.load_demo(); pipeline.run_analysis(); print_report()
        if a.serve:
            from campusshield.webapp import create_app
            print("\nDashboard: http://127.0.0.1:5000"); create_app().run(host="127.0.0.1", port=5000)
    elif a.cmd == "scan":
        ports = [int(p) for p in a.ports.split(",")] if a.ports else None
        print(f"Scanning {a.target} ... (only scan networks you are authorised to test)")
        found = discovery.scan_network(a.target, ports, use_nmap=a.nmap, allow_public=a.allow_public)
        for asset in found:
            db.upsert_asset(asset)
        db.log("cli", "scan", f"{a.target}: {len(found)} hosts")
        pipeline.run_analysis(); print_report()
    elif a.cmd == "audit":
        text = open(a.file).read()
        issues, _ = acl_audit.audit_config(text)
        for i in issues:
            print(f"[{i['severity'].upper():<8}] {i['acl']} line {i['line_no']}: {i['issue']}\n    {i['detail']}\n    Fix: {i['fix']}")
        print(f"\n{len(issues)} issue(s) found.")
        return 1 if any(i["severity"] == "critical" for i in issues) else 0
    elif a.cmd == "baseline":
        for z, cfg in recommender.baseline_configs().items():
            print(f"! ===== {z} =====\n{cfg}\n")
    elif a.cmd == "serve":
        from campusshield.webapp import create_app
        pipeline.run_analysis(); create_app().run(host=a.host, port=a.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
