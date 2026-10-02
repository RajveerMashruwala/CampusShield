import os
import re
import shutil
import tempfile
import unittest

os.environ.setdefault("CAMPUSSHIELD_DATA", tempfile.mkdtemp())

from campusshield import acl_audit, config, db, demo_data, discovery, enforcement, pipeline, recommender, risk  # noqa: E402
from campusshield.webapp import create_app  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["CAMPUSSHIELD_DATA"] = self.tmp
        demo_data.load_demo()
        pipeline.run_analysis()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestRisk(unittest.TestCase):
    def test_formula_and_bands(self):
        self.assertEqual(risk.score(9.8, 5, 1.5), 73.5)
        self.assertEqual(risk.priority(73.5), "critical")
        self.assertEqual(risk.priority(30), "high")
        self.assertEqual(risk.priority(10), "medium")
        self.assertEqual(risk.priority(3), "low")


class TestDiscovery(unittest.TestCase):
    def test_rejects_public_and_large(self):
        with self.assertRaises(ValueError):
            discovery.validate_target("8.8.8.0/24")
        with self.assertRaises(ValueError):
            discovery.validate_target("10.0.0.0/8")
        self.assertEqual(discovery.validate_target("192.168.1.0/24").num_addresses, 256)

    def test_scan_localhost_finds_open_port(self):
        import socket
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
        port = srv.getsockname()[1]
        try:
            found = discovery.scan_host("127.0.0.1", [port], timeout=0.5)
            self.assertIn(port, found)
        finally:
            srv.close()


class TestAclAudit(unittest.TestCase):
    def test_parse_wildcard_and_ports(self):
        r = acl_audit.parse_rule("X", 1, "permit tcp 10.10.30.0 0.0.0.255 host 10.10.50.20 eq 443 log")
        self.assertEqual(str(r.src), "10.10.30.0/24")
        self.assertEqual(str(r.dst), "10.10.50.20/32")
        self.assertEqual(r.dport, (443, 443))
        self.assertTrue(r.log)

    def test_detects_known_problems(self):
        text = (config.BASE_DIR / "sample_configs" / "running-config-insecure.txt").read_text()
        issues, _ = acl_audit.audit_config(text)
        names = {i["issue"] for i in issues}
        self.assertIn("permit ip any any", names)
        self.assertIn("Shadowed rule (never matches)", names)
        self.assertIn("Redundant rule", names)
        self.assertIn("Risky service permitted: Telnet", names)
        self.assertIn("Risky service permitted: SMB", names)
        self.assertIn("VLAN interface has no inbound ACL", names)
        self.assertIn("Missing final 'deny ip any any log'", names)

    def test_baseline_acls_are_clean(self):
        text = "\n".join(recommender.baseline_configs().values())
        issues, _ = acl_audit.audit_config(text)
        bad = [i for i in issues if i["severity"] in ("critical", "high")]
        self.assertEqual(bad, [], bad)


class TestPipeline(Base):
    def test_demo_generates_findings_and_recs(self):
        s = pipeline.summary()
        self.assertEqual(s["assets"], len(demo_data.DEMO_HOSTS))
        self.assertGreater(s["open_findings"], 10)
        self.assertGreater(s["pending_recs"], 5)
        self.assertGreater(s["priorities"]["critical"], 0)

    def test_sequence_numbers_unique_per_acl(self):
        seen = {}
        for r in db.recs():
            cur = None
            for line in r["config_text"].splitlines():
                m = re.match(r"ip access-list extended (\S+)", line)
                if m:
                    cur = m.group(1); continue
                m = re.match(r"\s+(\d+) (deny|permit)", line)
                if m:
                    key = (cur, m.group(1))
                    self.assertNotIn(key, seen, f"duplicate seq {key}")
                    seen[key] = r["id"]


class TestEnforcement(Base):
    def _enforceable(self):
        return next(r for r in db.recs() if r["enforceable"] and r["control_type"] == "acl_block")

    def test_requires_approval(self):
        res = enforcement.apply_recommendation(self._enforceable()["id"])
        self.assertFalse(res["ok"])

    def test_apply_updates_config_and_mitigates(self):
        rec = self._enforceable()
        before_risk = pipeline.summary()["aggregate_risk"]
        db.set_rec_status(rec["id"], "approved")
        res = enforcement.apply_recommendation(rec["id"])
        self.assertTrue(res["ok"], res)
        cfg = config.running_config_path().read_text()
        self.assertIn(f"host {rec['asset_ip']}", cfg)
        self.assertEqual(db.get_rec(rec["id"])["status"], "applied")
        self.assertLess(pipeline.summary()["aggregate_risk"], before_risk)

    def test_rollback_on_failed_verification(self):
        rec = self._enforceable()
        db.set_rec_status(rec["id"], "approved")
        before = config.running_config_path().read_text()
        dev = enforcement.FileDevice()
        dev.verify = lambda lines: False
        res = enforcement.apply_recommendation(rec["id"], device=dev)
        self.assertFalse(res["ok"])
        self.assertEqual(config.running_config_path().read_text(), before)
        self.assertEqual(db.get_rec(rec["id"])["status"], "failed")

    def test_dry_run_does_not_touch_config(self):
        rec = self._enforceable()
        db.set_rec_status(rec["id"], "approved")
        before = config.running_config_path().read_text()
        res = enforcement.apply_recommendation(rec["id"], dry_run=True)
        self.assertTrue(res["ok"])
        self.assertEqual(config.running_config_path().read_text(), before)

    def test_rollback_lines(self):
        lines = ["ip access-list extended A", " 10 deny ip host 1.1.1.1 any log"]
        self.assertEqual(enforcement.rollback_lines(lines), ["ip access-list extended A", " no 10"])


class TestWeb(Base):
    def setUp(self):
        super().setUp()
        self.client = create_app().test_client()

    def test_pages_render(self):
        for path in ("/", "/assets", "/findings", "/acl", "/recommendations", "/baseline", "/log",
                     "/asset/10.10.50.20", "/api/summary", "/api/assets", "/api/findings"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_post_requires_csrf(self):
        self.assertEqual(self.client.post("/analyze").status_code, 400)

    def test_approve_flow_with_csrf(self):
        self.client.get("/")
        with self.client.session_transaction() as s:
            token = s["csrf"]
        rid = next(r["id"] for r in db.recs() if r["enforceable"])
        r = self.client.post(f"/rec/{rid}/approve", data={"csrf": token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(db.get_rec(rid)["status"], "approved")

    def test_scan_rejects_public_target(self):
        self.client.get("/")
        with self.client.session_transaction() as s:
            token = s["csrf"]
        r = self.client.post("/scan", data={"csrf": token, "target": "8.8.8.0/24"}, follow_redirects=True)
        self.assertIn(b"Scan rejected", r.data)

    def test_basic_auth(self):
        os.environ["CAMPUSSHIELD_PASSWORD"] = "s3cret"
        try:
            c = create_app().test_client()
            self.assertEqual(c.get("/").status_code, 401)
            import base64
            h = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret").decode()}
            self.assertEqual(c.get("/", headers=h).status_code, 200)
        finally:
            del os.environ["CAMPUSSHIELD_PASSWORD"]


if __name__ == "__main__":
    unittest.main()
