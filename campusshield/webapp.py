"""Flask dashboard + JSON API."""
import hmac
import os
import secrets
import threading

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for

from . import __version__, acl_audit, config, db, demo_data, discovery, enforcement, pipeline, recommender

SCAN = {"running": False, "message": "idle"}


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("CAMPUSSHIELD_SECRET") or secrets.token_hex(16)
    db.init()

    @app.before_request
    def guard():
        pw = os.environ.get("CAMPUSSHIELD_PASSWORD")
        if pw:
            auth = request.authorization
            if not auth or not hmac.compare_digest(auth.password or "", pw):
                return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="CampusShield"'})
        if request.method == "POST":
            token = session.get("csrf")
            if not token or not hmac.compare_digest(token, request.form.get("csrf", "")):
                abort(400, "Invalid CSRF token")

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        device = "cisco-ios (ssh)" if os.environ.get("CAMPUSSHIELD_DEVICE") == "ssh" else "simulated device (file)"
        return {"csrf": session["csrf"], "version": __version__, "device": device}

    @app.route("/")
    def index():
        return render_template("index.html", s=pipeline.summary(), scan=SCAN)

    @app.route("/assets")
    def assets():
        return render_template("assets.html", assets=db.assets())

    @app.route("/asset/<ip>")
    def asset(ip):
        a = db.asset(ip) or abort(404)
        return render_template("asset.html", a=a, findings=db.findings(ip),
                               recs=[r for r in db.recs() if r["asset_ip"] == ip])

    @app.route("/findings")
    def findings():
        return render_template("findings.html", findings=db.findings())

    @app.route("/acl")
    def acl():
        p = config.running_config_path()
        return render_template("acl.html", issues=db.acl_issues(), cfg=p.read_text() if p.exists() else "")

    @app.route("/acl/upload", methods=["POST"])
    def acl_upload():
        text = request.form.get("config", "")
        if not text.strip():
            flash("Paste a Cisco IOS running-config / ACL text first.")
        else:
            config.data_dir().mkdir(parents=True, exist_ok=True)
            config.running_config_path().write_text(text.replace("\r\n", "\n"))
            pipeline.run_acl_audit()
            db.log("admin", "acl-upload", f"{len(text)} bytes")
            flash("Configuration loaded and audited.")
        return redirect(url_for("acl"))

    @app.route("/recommendations")
    def recommendations():
        return render_template("recommendations.html", recs=db.recs())

    @app.route("/rec/<int:rec_id>/<action>", methods=["POST"])
    def rec_action(rec_id, action):
        rec = db.get_rec(rec_id) or abort(404)
        if action == "approve" and rec["status"] == "pending":
            db.set_rec_status(rec_id, "approved"); db.log("admin", "approve", f"rec {rec_id}: {rec['title']}")
            flash(f"Recommendation #{rec_id} approved.")
        elif action == "reject" and rec["status"] in ("pending", "approved"):
            db.set_rec_status(rec_id, "rejected"); db.log("admin", "reject", f"rec {rec_id}")
            flash(f"Recommendation #{rec_id} rejected.")
        elif action in ("apply", "dryrun"):
            res = enforcement.apply_recommendation(rec_id, dry_run=(action == "dryrun"))
            flash(res["message"])
        else:
            abort(400)
        return redirect(url_for("recommendations"))

    @app.route("/baseline")
    def baseline():
        return render_template("baseline.html", configs=recommender.baseline_configs())

    @app.route("/log")
    def log():
        return render_template("log.html", rows=db.audit_log())

    @app.route("/scan", methods=["POST"])
    def scan():
        target = request.form.get("target", "").strip()
        if SCAN["running"]:
            flash("A scan is already running.")
            return redirect(url_for("index"))
        try:
            discovery.validate_target(target)
        except ValueError as e:
            flash(f"Scan rejected: {e}")
            return redirect(url_for("index"))

        def job():
            SCAN.update(running=True, message=f"scanning {target} ...")
            try:
                found = discovery.scan_network(target)
                for a in found:
                    db.upsert_asset(a)
                db.log("admin", "scan", f"{target}: {len(found)} hosts")
                pipeline.run_analysis()
                SCAN["message"] = f"last scan: {target} -> {len(found)} host(s)"
            except Exception as e:
                SCAN["message"] = f"scan failed: {e}"
            finally:
                SCAN["running"] = False

        threading.Thread(target=job, daemon=True).start()
        flash(f"Scan of {target} started.")
        return redirect(url_for("index"))

    @app.route("/demo", methods=["POST"])
    def demo():
        demo_data.load_demo(); pipeline.run_analysis()
        flash("Demo data loaded.")
        return redirect(url_for("index"))

    @app.route("/analyze", methods=["POST"])
    def analyze():
        r = pipeline.run_analysis()
        flash(f"Analysis complete: {r['findings']} findings, {r['recommendations']} recommendations.")
        return redirect(url_for("index"))

    @app.route("/api/summary")
    def api_summary():
        return jsonify(pipeline.summary())

    @app.route("/api/assets")
    def api_assets():
        return jsonify(db.assets())

    @app.route("/api/findings")
    def api_findings():
        return jsonify(db.findings())

    return app
