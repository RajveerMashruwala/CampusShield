"""Controlled enforcement with backup, verification and rollback.

Devices:
  * FileDevice (default) - a simulated device backed by data/running-config.txt. Safe for demos/tests.
  * SSHDevice            - real Cisco IOS via Netmiko (optional; env CAMPUSSHIELD_SSH_HOST/USER/PASS).
Nothing is ever pushed unless the recommendation was explicitly approved by an administrator.
"""
import os
import re
import time

from . import acl_audit, config, db


def _strip_seq(entry: str) -> str:
    return re.sub(r"^\d+\s+", "", entry.strip())


def parse_blocks(lines):
    """Group config lines into {acl: [entry,...]} (ignores resequence/global lines)."""
    blocks, cur = {}, None
    for line in lines:
        s = line.strip()
        m = re.match(r"ip access-list extended (\S+)", s)
        if m:
            cur = m.group(1); blocks.setdefault(cur, []); continue
        if s in ("!", "") or s.startswith("interface"):
            cur = None
            continue
        if s.startswith("ip access-list resequence"):
            continue
        if cur and line[:1].isspace():
            blocks[cur].append(s)
    return blocks


def rollback_lines(lines):
    """Commands that undo sequence-numbered ACL entries."""
    out = []
    for acl, entries in parse_blocks(lines).items():
        seqs = [re.match(r"(\d+)\s", e).group(1) for e in entries if re.match(r"\d+\s", e)]
        if seqs:
            out.append(f"ip access-list extended {acl}")
            out += [f" no {s}" for s in seqs]
    return out


class FileDevice:
    name = "simulated-device (file)"

    def __init__(self, path=None):
        self.path = path or config.running_config_path()

    def get_config(self):
        return self.path.read_text() if self.path.exists() else ""

    def restore(self, text):
        self.path.write_text(text)

    def apply(self, lines):
        new = parse_blocks(lines)
        text = self.get_config()
        existing = {a: {_strip_seq(e) for e in es} for a, es in acl_audit_blocks(text).items()}
        out, done = [], set()
        for line in text.splitlines():
            out.append(line)
            m = re.match(r"ip access-list extended (\S+)", line.strip())
            if m and m.group(1) in new:
                acl = m.group(1); done.add(acl)
                for e in new[acl]:
                    if _strip_seq(e) not in existing.get(acl, set()):
                        out.append(" " + _strip_seq(e))
        for acl, entries in new.items():
            if acl not in done:
                out += [f"ip access-list extended {acl}"] + [" " + _strip_seq(e) for e in entries] + ["!"]
        self.path.write_text("\n".join(out) + "\n")

    def verify(self, lines):
        have = {a: {_strip_seq(e) for e in es} for a, es in acl_audit_blocks(self.get_config()).items()}
        return all(_strip_seq(e) in have.get(a, set()) for a, es in parse_blocks(lines).items() for e in es)


def acl_audit_blocks(text):
    return parse_blocks(text.splitlines())


class SSHDevice:  # pragma: no cover - needs real hardware
    name = "cisco-ios (ssh)"

    def __init__(self):
        try:
            from netmiko import ConnectHandler
        except ImportError as e:
            raise RuntimeError("Install netmiko (pip install netmiko) to enable SSH enforcement.") from e
        self.params = {"device_type": "cisco_ios", "host": os.environ["CAMPUSSHIELD_SSH_HOST"],
                       "username": os.environ["CAMPUSSHIELD_SSH_USER"], "password": os.environ["CAMPUSSHIELD_SSH_PASS"],
                       "secret": os.environ.get("CAMPUSSHIELD_SSH_ENABLE", "")}
        self._connect = ConnectHandler

    def _run(self, fn):
        c = self._connect(**self.params)
        try:
            if self.params["secret"]:
                c.enable()
            return fn(c)
        finally:
            c.disconnect()

    def get_config(self):
        return self._run(lambda c: c.send_command("show running-config"))

    def restore(self, text):
        raise RuntimeError("Automatic full restore over SSH is not supported; use rollback commands.")

    def apply(self, lines):
        self._run(lambda c: c.send_config_set(lines))

    def verify(self, lines):
        have = {a: {_strip_seq(e) for e in es} for a, es in acl_audit_blocks(self.get_config()).items()}
        return all(_strip_seq(e) in have.get(a, set()) for a, es in parse_blocks(lines).items() for e in es)


def get_device():
    return SSHDevice() if os.environ.get("CAMPUSSHIELD_DEVICE", "file") == "ssh" else FileDevice()


def _lines(rec):
    return [l for l in rec["config_text"].splitlines() if l.strip() and l.strip() != "!"]


def apply_recommendation(rec_id, actor="admin", dry_run=False, device=None):
    """Apply an approved recommendation. Returns {'ok': bool, 'message': str}."""
    rec = db.get_rec(rec_id)
    if not rec:
        return {"ok": False, "message": "Recommendation not found."}
    if not rec["enforceable"]:
        return {"ok": False, "message": "This recommendation is manual (not enforceable automatically)."}
    if rec["status"] != "approved":
        return {"ok": False, "message": "Recommendation must be approved by an administrator first."}
    device = device or get_device()
    lines = _lines(rec)
    ts = time.strftime("%Y%m%d-%H%M%S")
    config.output_dir().mkdir(parents=True, exist_ok=True)
    if dry_run:
        out = config.output_dir() / f"rec{rec_id}-{ts}.cfg"
        out.write_text(rec["config_text"] + "\n")
        db.log(actor, "dry-run", f"rec {rec_id} written to {out}")
        return {"ok": True, "message": f"Dry run: configuration written to {out}"}

    before = device.get_config()
    config.backup_dir().mkdir(parents=True, exist_ok=True)
    (config.backup_dir() / f"backup-rec{rec_id}-{ts}.txt").write_text(before)
    try:
        device.apply(lines)
        ok = device.verify(lines)
    except Exception as e:
        ok, err = False, str(e)
    else:
        err = "verification failed"
    if not ok:
        try:
            device.restore(before) if isinstance(device, FileDevice) else device.apply(rollback_lines(lines))
        except Exception as e:
            err += f"; ROLLBACK ERROR: {e}"
        db.log(actor, "apply-failed", f"rec {rec_id}: {err}; rolled back")
        db.set_rec_status(rec_id, "failed")
        return {"ok": False, "message": f"Apply failed ({err}). Configuration rolled back."}
    db.set_rec_status(rec_id, "applied")
    db.log(actor, "apply", f"rec {rec_id} applied to {device.name}: {rec['title']}")
    from . import pipeline  # late import avoids cycle
    pipeline.run_analysis()
    return {"ok": True, "message": f"Applied to {device.name} and re-audited."}
