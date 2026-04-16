# =============================================================================
# app.py — Flask Web Application
# AI-Based Cyber Attack Detection and Prevention System
#
# Routes:
#   GET  /                    → SOC dashboard UI
#   GET  /embed               → Agent embed instructions page
#   POST /login               → attack detection, ML prediction, blocking logic
#   GET  /dashboard           → admin view of all attack logs (JSON API)
#   GET  /api/status          → health check
#   POST /api/agent/report    → receive telemetry from monitored sites
#   GET  /api/sites           → list of registered monitored sites
#   GET  /api/agent/logs      → logs filtered by site_id
# Security model:
#   - /api/agent/report  → requires valid (site_id + api_key) pair
#   - /api/agent/logs    → requires valid (site_id + api_key); returns ONLY that site's data
#   - /api/sites         → public, but api_key is NEVER exposed
#   - /api/admin/sites   → full listing incl. keys, protected by ADMIN_KEY env var
# =============================================================================

import os
import pickle
import hashlib
import hmac

import pandas as pd
from flask import Flask, jsonify, request, send_from_directory

from utils import get_response, get_severity
from database import (
    init_db, seed_demo_data,
    db_log_attack, db_get_all_logs, db_get_total_events,
    db_block_ip, db_is_blocked, db_get_blocked_ips,
    db_add_history, db_get_history_count,
    db_increment_failed, db_get_failed_count,
    db_get_sites, db_validate_api_key, db_get_logs_by_site,
)

# ---------------------------------------------------------------------------
# 1. Load ML artefacts
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _load(filename: str):
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Artefact '{filename}' not found. Run train_model.py first."
        )
    with open(path, "rb") as f:
        return pickle.load(f)

model    = _load("attack_model.pkl")
encoders = _load("encoders.pkl")
columns  = _load("columns.pkl")

print("[APP] Model, encoders, and columns loaded successfully.")

# ---------------------------------------------------------------------------
# 2. Admin key (set SOC_ADMIN_KEY env var in production)
# ---------------------------------------------------------------------------
ADMIN_KEY = os.environ.get("SOC_ADMIN_KEY", "soc-admin-secret-change-me")

def _check_admin(req) -> bool:
    """Return True if the request carries a valid admin key."""
    key = req.headers.get("X-Admin-Key") or req.args.get("admin_key") or ""
    return hmac.compare_digest(key, ADMIN_KEY)

# ---------------------------------------------------------------------------
# 3. Flask app initialisation
# ---------------------------------------------------------------------------
STATIC_DIR = os.path.join(BASE_DIR, "static")
app = Flask(__name__, static_folder=STATIC_DIR)


@app.after_request
def add_cors(response):
    """Allow cross-origin requests so monitored sites can POST to us."""
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# ---------------------------------------------------------------------------
# 3. Initialize database + seed demo data
# ---------------------------------------------------------------------------
init_db()
seed_demo_data()

# ---------------------------------------------------------------------------
# 4. Helper functions
# ---------------------------------------------------------------------------

def detect_bruteforce(ip: str) -> bool:
    return db_get_failed_count(ip) > 5


def log_attack(ip: str, attack: str, severity: str, **kwargs) -> None:
    db_log_attack(ip, attack, severity, **kwargs)


def auto_block(ip: str, severity: str) -> str:
    if severity == "Critical":
        db_block_ip(ip, severity)
        return "Permanently blocked"
    elif severity == "High":
        db_block_ip(ip, severity)
        return "Temporarily blocked (24 h)"
    else:
        return "Monitoring"


def is_blocked(ip: str) -> bool:
    return db_is_blocked(ip)


def adaptive_action(ip: str, attack: str, severity: str) -> str:
    db_add_history(ip, attack)
    count = db_get_history_count(ip)
    if count >= 5:
        db_block_ip(ip, "Critical")
        return "Blocked (repeated offender)"
    elif count >= 3:
        return "Alert — repeated attack detected"
    else:
        return "Monitoring"


def build_feature_row(ip: str, protocol: str = "tcp",
                      service: str = "http", flag: str = "SF") -> pd.DataFrame:
    failed = db_get_failed_count(ip)
    row = {col: 0 for col in columns}
    row["duration"]          = 0
    row["src_bytes"]         = 215
    row["dst_bytes"]         = 45076
    row["land"]              = 0
    row["wrong_fragment"]    = 0
    row["urgent"]            = 0
    row["hot"]               = 0
    row["num_failed_logins"] = failed
    row["logged_in"]         = 0
    row["count"]             = max(failed, 1)
    row["srv_count"]         = max(failed, 1)
    row["same_srv_rate"]     = 1.0
    row["serror_rate"]       = 0.0
    row["rerror_rate"]       = min(1.0, failed / 10)

    for col, le in encoders.items():
        val_map = {"protocol_type": protocol, "service": service, "flag": flag}
        raw_val = val_map.get(col, "tcp")
        if raw_val in le.classes_:
            row[col] = int(le.transform([raw_val])[0])
        else:
            row[col] = 0

    return pd.DataFrame([row])[columns]


# GeoIP country name lookup (lightweight dict — no external deps)
_CC_TO_NAME = {
    "CN": "China", "RU": "Russia", "US": "United States", "BR": "Brazil",
    "IN": "India", "DE": "Germany", "KP": "North Korea", "IR": "Iran",
    "UA": "Ukraine", "NG": "Nigeria", "FR": "France", "GB": "United Kingdom",
    "JP": "Japan", "KR": "South Korea", "PK": "Pakistan", "BD": "Bangladesh",
    "ID": "Indonesia", "VN": "Vietnam", "TR": "Turkey", "MX": "Mexico",
}

def _country_name(code: str) -> str:
    return _CC_TO_NAME.get((code or "").upper(), code or "Unknown")


# ---------------------------------------------------------------------------
# 5. Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Serve the SOC dashboard UI."""
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/embed", methods=["GET"])
def embed():
    """Serve the agent embed instructions page."""
    return send_from_directory(STATIC_DIR, "embed.html")


@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({"status": "ok", "message": "Website Running Securely"}), 200


# ---- Original login endpoint (unchanged) ----

@app.route("/login", methods=["POST"])
def login():
    ip   = request.remote_addr or "0.0.0.0"
    data = request.get_json(silent=True) or {}

    if is_blocked(ip):
        return jsonify({
            "ip": ip, "attack": "blocked", "severity": "N/A",
            "action": "Request rejected",
            "message": "Your IP is blocked due to suspicious activity.",
        }), 403

    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        db_increment_failed(ip)

    is_brute = detect_bruteforce(ip)
    if is_brute:
        attack_type = "bruteforce"
        severity    = get_severity(attack_type)
        response    = get_response(severity)
        action      = auto_block(ip, severity)
        log_attack(ip, attack_type, severity)
        return jsonify({
            "ip": ip, "attack": attack_type, "severity": severity,
            "action": action, "message": response,
        }), 403

    feature_df  = build_feature_row(ip)
    prediction  = model.predict(feature_df)[0]
    attack_type = str(prediction).lower().strip()
    severity    = get_severity(attack_type)
    response    = get_response(severity)
    adaptive_msg= adaptive_action(ip, attack_type, severity)
    block_action= auto_block(ip, severity)
    action      = block_action if block_action != "Monitoring" else adaptive_msg

    log_attack(ip, attack_type, severity)
    return jsonify({
        "ip": ip, "attack": attack_type, "severity": severity,
        "action": action, "message": response,
    }), 200


# ---- Dashboard ----

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return jsonify({
        "total_events": db_get_total_events(),
        "blocked_ips":  db_get_blocked_ips(),
        "attack_log":   db_get_all_logs(),
    }), 200


# ---- Agent Report (the key new endpoint) ----

@app.route("/api/agent/report", methods=["POST", "OPTIONS"])
def agent_report():
    """
    Receive telemetry from a monitored site's embedded agent.js.

    Expected JSON body:
        site_id, api_key, ip, method, path, user_agent,
        referer, bytes_in, country (optional), city (optional), asn (optional)

    Returns the ML prediction result so the site can optionally act on it.
    """
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}

    site_id = data.get("site_id", "unknown")
    api_key = data.get("api_key", "")
    ip      = data.get("ip") or request.remote_addr or "0.0.0.0"

    # Strict API key validation — no exceptions, no demo bypass
    if not site_id or not api_key:
        return jsonify({"error": "site_id and api_key are required"}), 400
    if not db_validate_api_key(site_id, api_key):
        return jsonify({"error": "Invalid site_id or api_key"}), 401

    method     = data.get("method", "GET")
    path       = data.get("path", "/")
    user_agent = data.get("user_agent", "")
    referer    = data.get("referer", "")
    country    = data.get("country", "")
    city       = data.get("city", "")
    asn        = data.get("asn", "")
    bytes_in   = int(data.get("bytes_in", 0) or 0)

    # --- Blocked IP check ---
    if is_blocked(ip):
        return jsonify({
            "ip": ip, "attack": "blocked", "severity": "N/A",
            "action": "Request rejected — IP is blocked",
        }), 403

    # --- ML prediction ---
    feature_df  = build_feature_row(ip)
    prediction  = model.predict(feature_df)[0]
    attack_type = str(prediction).lower().strip()
    severity    = get_severity(attack_type)

    # --- Adaptive & auto-block ---
    adaptive_msg = adaptive_action(ip, attack_type, severity)
    block_action = auto_block(ip, severity)
    action       = block_action if block_action != "Monitoring" else adaptive_msg

    # --- Log with full metadata ---
    log_attack(
        ip, attack_type, severity,
        site_id    = site_id,
        user_agent = user_agent,
        method     = method,
        path       = path,
        referer    = referer,
        country    = country,
        city       = city,
        asn        = asn,
        bytes_in   = bytes_in,
    )

    return jsonify({
        "ip":         ip,
        "attack":     attack_type,
        "severity":   severity,
        "action":     action,
        "site_id":    site_id,
        "country":    country or "Unknown",
    }), 200


# ---- Sites registry (public — api_key NEVER exposed) ----

@app.route("/api/sites", methods=["GET"])
def api_sites():
    """Return monitored sites WITHOUT api_key. Safe for public dashboard."""
    from database import get_db
    sites = db_get_sites()
    result = []
    for s in sites:
        with get_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM attack_log WHERE site_id = ?", (s["id"],)
            ).fetchone()[0]
            attacks = conn.execute(
                "SELECT COUNT(*) FROM attack_log WHERE site_id = ? AND severity != 'None'",
                (s["id"],)
            ).fetchone()[0]
        # Strip api_key from public response
        result.append({
            "id":           s["id"],
            "name":         s["name"],
            "url":          s["url"],
            "created_at":   s["created_at"],
            "total_events": count,
            "total_attacks":attacks,
        })
    return jsonify(result), 200


# ---- Admin-only: full site listing with api_keys ----

@app.route("/api/admin/sites", methods=["GET"])
def api_admin_sites():
    """Return full site info including api_keys — admin key required."""
    if not _check_admin(request):
        return jsonify({"error": "Admin key required (X-Admin-Key header or ?admin_key=)"}), 403
    from database import get_db
    sites = db_get_sites()
    result = []
    for s in sites:
        with get_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM attack_log WHERE site_id = ?", (s["id"],)
            ).fetchone()[0]
            attacks = conn.execute(
                "SELECT COUNT(*) FROM attack_log WHERE site_id = ? AND severity != 'None'",
                (s["id"],)
            ).fetchone()[0]
        result.append({**dict(s), "total_events": count, "total_attacks": attacks})
    return jsonify(result), 200


# ---- Agent logs by site (api_key required — site sees ONLY its own data) ----

@app.route("/api/agent/logs", methods=["GET"])
def api_agent_logs():
    """
    Return attack logs for a site.
    Requires matching (site_id + api_key) — a site can ONLY read its own data.
    Admin key bypasses this restriction so the SOC dashboard can read all sites.
    """
    site_id = request.args.get("site_id", "")
    api_key = request.args.get("api_key", "")

    if not site_id:
        return jsonify({"error": "site_id required"}), 400

    # SOC dashboard (admin) can access any site without per-site api_key
    is_admin = _check_admin(request)

    if not is_admin:
        # Regular site access: must prove ownership via api_key
        if not api_key:
            return jsonify({"error": "api_key required to access site logs"}), 401
        if not db_validate_api_key(site_id, api_key):
            return jsonify({"error": "Invalid site_id or api_key"}), 401

    logs = db_get_logs_by_site(site_id, limit=200)
    return jsonify({
        "site_id":    site_id,
        "total":      len(logs),
        "attack_log": logs,
    }), 200


# ---------------------------------------------------------------------------
# 6. Entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)