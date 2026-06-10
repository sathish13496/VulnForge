"""
LinArmor Flask Web Application

Serves the frontend UI and provides REST API endpoints
for scan management, findings, and report generation.
Uses WebSocket (via Flask-SocketIO) for real-time scan log streaming.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_socketio import SocketIO, emit

from linarmor.config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG, SECRET_KEY,
    SCAN_TYPES, STATIC_DIR, TEMPLATES_DIR, ensure_directories,
)
from linarmor.core.engine import ScanEngine
from linarmor.core.target import ScanStatus
from linarmor.cve.matcher import CVEMatcher
from linarmor.cve.database import CVEDatabase
from linarmor.cve.updater import NVDUpdater
from linarmor.reporting.generators import JSONReporter, HTMLReporter

# Import all scan modules
from linarmor.modules.ssh import SSHModule
from linarmor.modules.services import ServicesModule
from linarmor.modules.kernel import KernelModule
from linarmor.modules.credentials import CredentialsModule
from linarmor.modules.docker import DockerModule
from linarmor.modules.nfs import NFSModule
from linarmor.modules.samba import SambaModule
from linarmor.modules.sensitive_files import SensitiveFilesModule
from linarmor.modules.suid import SUIDModule
from linarmor.modules.permissions import PermissionsModule
from linarmor.modules.cron import CronModule

logger = logging.getLogger("linarmor.app")

# ──────────────────────────────────────────────
# Flask App Setup
# ──────────────────────────────────────────────

app = Flask(
    __name__,
    static_folder=str(STATIC_DIR),
    template_folder=str(TEMPLATES_DIR),
)
app.config["SECRET_KEY"] = SECRET_KEY

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Global scan engine instance
engine = ScanEngine()
cve_db = CVEDatabase()
cve_matcher = CVEMatcher(db=cve_db)


# ──────────────────────────────────────────────
# WebSocket Log Callback
# ──────────────────────────────────────────────

def websocket_log(level: str, message: str) -> None:
    """Emit scan log messages to connected WebSocket clients."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    socketio.emit("scan_log", {
        "time": timestamp,
        "level": level,
        "message": message,
    })


def websocket_status(status: dict) -> None:
    """Emit scan status updates to connected WebSocket clients."""
    socketio.emit("scan_status", status)


# Configure engine with WebSocket callbacks
engine = ScanEngine(log_callback=websocket_log)
engine.set_status_callback(websocket_status)


def _register_modules() -> None:
    """Register all scan modules with the engine."""
    modules = {
        "ssh": SSHModule(log_callback=websocket_log),
        "services": ServicesModule(log_callback=websocket_log),
        "kernel": KernelModule(log_callback=websocket_log),
        "credentials": CredentialsModule(log_callback=websocket_log),
        "docker": DockerModule(log_callback=websocket_log),
        "nfs": NFSModule(log_callback=websocket_log),
        "samba": SambaModule(log_callback=websocket_log),
        "sensitive_files": SensitiveFilesModule(log_callback=websocket_log),
        "suid": SUIDModule(log_callback=websocket_log),
        "permissions": PermissionsModule(log_callback=websocket_log),
        "cron": CronModule(log_callback=websocket_log),
    }
    for name, module in modules.items():
        engine.register_module(name, module)

_register_modules()


# ──────────────────────────────────────────────
# Frontend Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard page."""
    # Serve index.html from templates directory
    return send_from_directory(str(TEMPLATES_DIR), "index.html")


@app.route("/static/<path:filename>")
def serve_static(filename):
    """Serve static assets (CSS, JS, images)."""
    return send_from_directory(str(STATIC_DIR), filename)


# ──────────────────────────────────────────────
# Scan API Endpoints
# ──────────────────────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    """
    Start a new scan.

    POST body:
    {
        "target_ip": "192.168.1.100",
        "port_range": "1-65535",
        "scan_type": "full",
        "modules": ["ssh", "kernel", "services"]
    }
    """
    if engine.is_running:
        return jsonify({"error": "A scan is already running"}), 409

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    target_ip = data.get("target_ip", "").strip()
    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400

    scan_type = data.get("scan_type", "full")
    port_range = data.get("port_range")
    modules = data.get("modules")

    # Re-register modules for fresh scan
    _register_modules()

    # Configure and start
    engine.configure(
        ip=target_ip,
        scan_type=scan_type,
        port_range=port_range,
        modules=modules,
    )
    engine.start()

    return jsonify({
        "status": "started",
        "target": target_ip,
        "scan_type": scan_type,
    })


@app.route("/api/scan/status", methods=["GET"])
def scan_status():
    """Get current scan status."""
    return jsonify(engine.get_status())


@app.route("/api/scan/pause", methods=["POST"])
def pause_scan():
    """Pause the running scan."""
    engine.pause()
    return jsonify({"status": "paused"})


@app.route("/api/scan/resume", methods=["POST"])
def resume_scan():
    """Resume a paused scan."""
    engine.resume()
    return jsonify({"status": "resumed"})


@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    """Stop the running scan."""
    engine.stop()
    return jsonify({"status": "stopped"})


# ──────────────────────────────────────────────
# Findings API
# ──────────────────────────────────────────────

@app.route("/api/findings", methods=["GET"])
def get_findings():
    """Get all findings from the current/last scan."""
    target = engine.get_target()
    if not target:
        return jsonify({"findings": [], "total": 0})

    # Optional severity filter
    severity = request.args.get("severity")
    findings = [f.to_dict() for f in target.findings]

    if severity:
        findings = [f for f in findings if f["severity"] == severity]

    return jsonify({
        "findings": findings,
        "total": len(findings),
        "severity_counts": target.severity_counts,
    })


@app.route("/api/target", methods=["GET"])
def get_target():
    """Get full target information including services and findings."""
    target = engine.get_target()
    if not target:
        return jsonify({"error": "No scan data available"}), 404
    return jsonify(target.to_dict())


# ──────────────────────────────────────────────
# CVE API
# ──────────────────────────────────────────────

@app.route("/api/cve/<cve_id>", methods=["GET"])
def lookup_cve(cve_id):
    """Look up a specific CVE by ID."""
    entry = cve_matcher.lookup_cve(cve_id)
    if entry:
        return jsonify(entry.to_dict())
    return jsonify({"error": f"CVE {cve_id} not found"}), 404


@app.route("/api/cve/stats", methods=["GET"])
def cve_stats():
    """Get CVE database statistics."""
    return jsonify(cve_matcher.get_db_stats())


@app.route("/api/cve/update", methods=["POST"])
def update_cve_db():
    """Trigger a CVE database update."""
    updater = NVDUpdater(db=cve_db, log_callback=websocket_log)
    stats = updater.update()
    return jsonify({"status": "completed", "stats": stats})


# ──────────────────────────────────────────────
# Report API
# ──────────────────────────────────────────────

@app.route("/api/report/<report_format>", methods=["GET"])
def generate_report(report_format):
    """Generate and download a report."""
    target = engine.get_target()
    if not target:
        return jsonify({"error": "No scan data available for report"}), 404

    ensure_directories()

    if report_format == "json":
        reporter = JSONReporter()
        path = reporter.generate(target)
        return send_file(str(path), as_attachment=True, download_name=path.name)

    elif report_format == "html":
        reporter = HTMLReporter()
        path = reporter.generate(target)
        return send_file(str(path), as_attachment=True, download_name=path.name)

    elif report_format == "pdf":
        # Serve HTML report inline for browser print-to-PDF
        reporter = HTMLReporter()
        path = reporter.generate(target)
        return send_file(str(path), mimetype="text/html", download_name=path.name)

    return jsonify({"error": f"Unknown format: {report_format}"}), 400


# ──────────────────────────────────────────────
# WebSocket Events
# ──────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    """Client connected to WebSocket."""
    logger.info("WebSocket client connected")
    # Send current status if a scan is running
    emit("scan_status", engine.get_status())


@socketio.on("disconnect")
def handle_disconnect():
    """Client disconnected from WebSocket."""
    logger.info("WebSocket client disconnected")


# ──────────────────────────────────────────────
# App Runner
# ──────────────────────────────────────────────

def create_app() -> Flask:
    """Create and configure the Flask app."""
    ensure_directories()

    # Initialize CVE database
    try:
        cve_db.initialize()
    except Exception as e:
        logger.warning(f"Could not initialize CVE database: {e}")

    return app


def run_server(host: str = None, port: int = None, debug: bool = None) -> None:
    """Run the Flask-SocketIO server."""
    ensure_directories()

    h = host or FLASK_HOST
    p = port or FLASK_PORT
    d = debug if debug is not None else FLASK_DEBUG

    print(f"""
    ╔══════════════════════════════════════════╗
    ║     🛡️  LinArmor v1.0.0               ║
    ║     Security Misconfiguration Framework  ║
    ╠══════════════════════════════════════════╣
    ║  Web UI:  http://{h}:{p}              ║
    ║  API:     http://{h}:{p}/api          ║
    ║  Status:  Ready                          ║
    ╚══════════════════════════════════════════╝
    """)

    socketio.run(app, host=h, port=p, debug=d, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    run_server()
