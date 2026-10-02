"""SQLite persistence layer (standard library only)."""
import json
import sqlite3
import time
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(
  ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, vendor TEXT, os TEXT, device_type TEXT,
  vlan INTEGER, zone TEXT, criticality INTEGER, open_ports TEXT,
  first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, asset_ip TEXT, fkey TEXT, type TEXT, title TEXT, port INTEGER,
  cvss REAL, detail TEXT, risk_score REAL, priority TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS recommendations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, asset_ip TEXT, title TEXT, control_type TEXT,
  description TEXT, config_text TEXT, enforceable INTEGER, risk_score REAL, priority TEXT,
  status TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS acl_issues(
  id INTEGER PRIMARY KEY AUTOINCREMENT, acl TEXT, line_no INTEGER, severity TEXT, issue TEXT,
  detail TEXT, fix TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, detail TEXT);
"""


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def conn():
    config.data_dir().mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.db_path())
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn():
        pass


def reset():
    with conn() as c:
        for t in ("assets", "findings", "recommendations", "acl_issues", "audit_log"):
            c.execute(f"DELETE FROM {t}")


# ---- assets ---------------------------------------------------------------
def upsert_asset(a: dict):
    with conn() as c:
        c.execute(
            """INSERT INTO assets(ip,mac,hostname,vendor,os,device_type,vlan,zone,criticality,open_ports,first_seen,last_seen)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, hostname=excluded.hostname, vendor=excluded.vendor,
                 os=excluded.os, device_type=excluded.device_type, vlan=excluded.vlan, zone=excluded.zone,
                 criticality=excluded.criticality, open_ports=excluded.open_ports, last_seen=excluded.last_seen""",
            (a["ip"], a.get("mac"), a.get("hostname"), a.get("vendor"), a.get("os"), a.get("device_type"),
             a.get("vlan"), a.get("zone"), a.get("criticality", 2), json.dumps(a.get("open_ports", {})),
             now(), now()))


def _asset(row):
    d = dict(row)
    d["open_ports"] = {int(k): v for k, v in json.loads(d["open_ports"] or "{}").items()}
    return d


def assets():
    with conn() as c:
        return [_asset(r) for r in c.execute("SELECT * FROM assets ORDER BY vlan, ip")]


def asset(ip):
    with conn() as c:
        r = c.execute("SELECT * FROM assets WHERE ip=?", (ip,)).fetchone()
        return _asset(r) if r else None


# ---- findings -------------------------------------------------------------
def replace_findings(items):
    with conn() as c:
        c.execute("DELETE FROM findings")
        for f in items:
            c.execute(
                "INSERT INTO findings(asset_ip,fkey,type,title,port,cvss,detail,risk_score,priority,status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f["asset_ip"], f["fkey"], f["type"], f["title"], f.get("port"), f["cvss"], f["detail"],
                 f["risk_score"], f["priority"], f["status"]))


def findings(asset_ip=None):
    q, args = "SELECT * FROM findings", ()
    if asset_ip:
        q, args = q + " WHERE asset_ip=?", (asset_ip,)
    with conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY risk_score DESC", args)]


# ---- recommendations --------------------------------------------------------
def replace_recs(new):
    """Keep decided (approved/applied/rejected) recs; refresh pending ones."""
    keys = [r["key"] for r in new]
    with conn() as c:
        if keys:
            c.execute("DELETE FROM recommendations WHERE status='pending' AND key NOT IN (%s)"
                      % ",".join("?" * len(keys)), keys)
        else:
            c.execute("DELETE FROM recommendations WHERE status='pending'")
        for r in new:
            c.execute(
                """INSERT INTO recommendations(key,asset_ip,title,control_type,description,config_text,enforceable,
                       risk_score,priority,status,created) VALUES(?,?,?,?,?,?,?,?,?,'pending',?)
                   ON CONFLICT(key) DO UPDATE SET risk_score=excluded.risk_score, priority=excluded.priority
                   WHERE recommendations.status='pending'""",
                (r["key"], r["asset_ip"], r["title"], r["control_type"], r["description"], r["config_text"],
                 1 if r["enforceable"] else 0, r["risk_score"], r["priority"], now()))


def recs(status=None):
    q, args = "SELECT * FROM recommendations", ()
    if status:
        q, args = q + " WHERE status=?", (status,)
    with conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY risk_score DESC, id", args)]


def get_rec(rec_id):
    with conn() as c:
        r = c.execute("SELECT * FROM recommendations WHERE id=?", (rec_id,)).fetchone()
        return dict(r) if r else None


def set_rec_status(rec_id, status):
    with conn() as c:
        c.execute("UPDATE recommendations SET status=? WHERE id=?", (status, rec_id))


# ---- ACL issues / audit log -----------------------------------------------
def replace_acl_issues(items):
    with conn() as c:
        c.execute("DELETE FROM acl_issues")
        for i in items:
            c.execute("INSERT INTO acl_issues(acl,line_no,severity,issue,detail,fix) VALUES(?,?,?,?,?,?)",
                      (i["acl"], i.get("line_no"), i["severity"], i["issue"], i["detail"], i["fix"]))


def acl_issues():
    order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
    with conn() as c:
        return [dict(r) for r in c.execute(f"SELECT * FROM acl_issues ORDER BY {order}, acl, line_no")]


def log(actor, action, detail=""):
    with conn() as c:
        c.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES(?,?,?,?)", (now(), actor, action, detail))


def audit_log(limit=200):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]
