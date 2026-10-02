![CI](https://github.com/RajveerMashruwala/CampusShield/actions/workflows/ci.yml/badge.svg)
# CampusShield - Smart Campus Network Security

A working prototype that **identifies network assets, detects security weaknesses, and recommends / enforces
firewall & ACL controls** for a campus network.

```
Discover  ->  Assess  ->  Recommend  ->  Approve  ->  Enforce (backup, verify, rollback)  ->  Re-audit
```

| Stage | What it does | Module |
|---|---|---|
| Asset discovery | Threaded TCP scan, banner grab, ARP/MAC + vendor lookup, optional Nmap, VLAN/zone mapping | `discovery.py` |
| Weakness detection | Risky exposed ports (Telnet, SMB, RDP, Redis...), outdated-software banner signatures, zone-policy violations | `vulnscan.py` |
| Risk scoring | `Risk = CVSS x Asset criticality (1-5) x Exposure factor` -> critical / high / medium / low | `risk.py` |
| ACL / firewall audit | Parses Cisco IOS extended ACLs: `permit ip any any`, shadowed/redundant rules, risky permits, missing `deny ip any any log`, unprotected VLAN interfaces | `acl_audit.py` |
| Recommendation engine | Generates ready-to-apply ACL entries and baseline zone ACLs from the policy matrix | `recommender.py` |
| Enforcement | Admin approval -> backup -> apply -> verify -> automatic rollback; simulated device by default, Cisco IOS over SSH optional | `enforcement.py` |
| Dashboard + API | Flask web UI, CSRF protection, optional password, JSON API, audit log | `webapp.py` |

## Quick start (2 minutes, no network or hardware needed)

```bash
git clone https://github.com/RajveerMashruwala/campusshield.git
cd campusshield
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python run.py demo --serve        # loads a simulated campus, analyses it, opens dashboard at http://127.0.0.1:5000
```

Then in the dashboard: **Recommendations -> Approve -> Apply** on a "Block SMB ..." item and watch the **Aggregate risk**
drop and the simulated switch config (**ACL Audit** page) change. Everything is logged under **Audit Log**.

### Docker
```bash
docker build -t campusshield . && docker run -p 5000:5000 campusshield
```

## Command line

```bash
python run.py demo                                  # simulated campus + report in the terminal
python run.py scan --target 192.168.1.0/24          # real scan of a PRIVATE network you are authorised to test
python run.py scan --target 192.168.1.0/24 --nmap   # use Nmap (-sT -sV) if installed
python run.py audit --file sample_configs/running-config-insecure.txt   # audit an ACL config (exit code 1 if critical)
python run.py baseline                              # print baseline zone ACLs for every VLAN
python run.py serve --host 127.0.0.1 --port 5000    # dashboard only
```

## Configuration (environment variables)

| Variable | Purpose | Default |
|---|---|---|
| `CAMPUSSHIELD_DATA` | Folder for the SQLite DB, device config, backups, dry-run output | `./data` |
| `CAMPUSSHIELD_ZONES` | JSON file describing your VLANs/zones (see `zones.example.json`) | built-in 10.10.x.0/24 model |
| `CAMPUSSHIELD_PASSWORD` | Enables HTTP Basic auth (user `admin`) on the dashboard | off |
| `CAMPUSSHIELD_SECRET` | Flask session secret | random per start |
| `CAMPUSSHIELD_DEVICE` | `file` (simulated) or `ssh` (real Cisco IOS) | `file` |
| `CAMPUSSHIELD_SSH_HOST/USER/PASS/ENABLE` | Credentials for `ssh` mode (needs `pip install -r requirements-optional.txt`) | - |

> The web server binds to `127.0.0.1` by default. Set `CAMPUSSHIELD_PASSWORD` and use HTTPS (reverse proxy) before exposing it.

## Project structure

```
campusshield/
  run.py                      CLI entry point
  campusshield/
    config.py                 zones (VLANs), paths, policy constants
    db.py                     SQLite layer
    discovery.py              asset discovery
    vulnscan.py               weakness detection
    risk.py                   risk formula and priority bands
    acl_audit.py              Cisco ACL parser + auditor
    recommender.py            controls + baseline ACL generator
    enforcement.py            approval-gated apply / verify / rollback
    pipeline.py               end-to-end orchestration + dashboard summary
    demo_data.py              simulated campus
    webapp.py + templates/    dashboard and API
  sample_configs/             intentionally insecure demo running-config
  tests/                      unit + integration tests (unittest)
  .github/workflows/ci.yml    CI (Python 3.10-3.12)
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Using it on a real network

1. Define your VLANs in a zones JSON file and set `CAMPUSSHIELD_ZONES`.
2. Run `python run.py scan --target <your private CIDR>` (you must be authorised).
3. Paste your switch's `show running-config` into **ACL Audit -> Load a configuration** to audit it.
4. For live enforcement set `CAMPUSSHIELD_DEVICE=ssh` and the SSH variables. **Test on a lab device first** - the SSH path
   is implemented with Netmiko but could not be tested against real hardware here. Approved changes are backed up and verified;
   failures trigger rollback commands.

## Safety, ethics and limitations

- Only scan networks you own or have written permission to test. Public ranges and targets larger than 1024 addresses are refused by default.
- The scanner is non-intrusive (TCP connect + banner read); it never exploits anything.
- Vulnerability detection is heuristic (ports + banner signatures). Confirm with OpenVAS/Nessus before acting on important findings.
- ACL auditing supports Cisco IOS **extended named ACLs** (IPv4). Numbered ACLs, IPv6, object-groups and other vendors are future work.
- Enforcement is human-in-the-loop by design; automatic changes without approval are not possible.
- Port scanning is TCP only; UDP services and SNMP checks are future work.

## Roadmap
Suricata/syslog ingestion, SNMP/DHCP-log passive discovery, 802.1X dynamic VLANs, pfSense/iptables enforcement, IPv6, scheduled scans.

## License
MIT - see `LICENSE`.
