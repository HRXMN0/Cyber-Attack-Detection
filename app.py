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
#   - /api/agent/logs    → login required; admin sees all, companies see ONLY their own site
#   - /api/sites         → login required; scoped to the signed-in tenant
#   - /api/admin/sites   → admin-only full listing including API keys
# =============================================================================

import os
import pickle
import threading
import time

import bcrypt
import pandas as pd
from flask import (
    Flask, jsonify, request, send_from_directory,
    redirect, url_for, flash, render_template,
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)

from utils import get_response, get_severity
from database import (
    init_db, seed_demo_data,
    db_log_attack, db_get_all_logs, db_get_total_events,
    db_block_ip, db_is_blocked, db_get_blocked_ips,
    db_add_history, db_get_history_count,
    db_increment_failed, db_get_failed_count,
    db_get_sites, db_validate_api_key, db_get_logs_by_site,
    db_create_user, db_get_user_by_email, db_get_user_by_id, get_db,
    db_update_user_site,
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
# 2. Admin identity
# ---------------------------------------------------------------------------
ADMIN_EMAILS = {
    email.strip().lower()
    for email in os.environ.get("SOC_ADMIN_EMAILS", os.environ.get("SOC_ADMIN_EMAIL", "")).split(",")
    if email.strip()
}


def _effective_role(user_data: dict) -> str:
    """Resolve role from the DB row with optional env-based admin override."""
    role = str(user_data.get("role") or "analyst").lower().strip()
    email = str(user_data.get("email") or "").lower().strip()
    if role == "admin" or email in ADMIN_EMAILS:
        return "admin"
    return role or "analyst"

# ---------------------------------------------------------------------------
# 3. Flask app initialisation + Auth
# ---------------------------------------------------------------------------
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "static")
app = Flask(__name__, static_folder=STATIC_DIR, template_folder=TEMPLATE_DIR)
app.secret_key = os.environ.get("SECRET_KEY", "soc-super-secret-flask-key-change-in-prod")

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "auth_login"
login_manager.login_message = "Please login to access the SOC dashboard."
login_manager.login_message_category = "error"

class User(UserMixin):
    """Lightweight user object for Flask-Login."""
    def __init__(self, data: dict):
        self.id      = data["id"]
        self.name    = data["name"]
        self.email   = data["email"]
        self.role    = _effective_role(data)
        self.site_id = data.get("site_id")

@login_manager.user_loader
def load_user(user_id):
    data = db_get_user_by_id(int(user_id))
    return User(data) if data else None


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

def get_client_ip() -> str:
    """Resolve client IP with optional X-Forwarded-For support for local simulation."""
    forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or (request.remote_addr or "0.0.0.0")
    return request.remote_addr or "0.0.0.0"


def detect_bruteforce(ip: str) -> bool:
    return db_get_failed_count(ip) > 5


def is_admin_user() -> bool:
    return current_user.is_authenticated and str(getattr(current_user, "role", "")).lower() == "admin"


def log_attack(ip: str, attack: str, severity: str, **kwargs) -> None:
    db_log_attack(ip, attack, severity, **kwargs)


def auto_block(ip: str, severity: str, site_id: str = "local") -> str:
    if severity == "Critical":
        db_block_ip(ip, severity, site_id=site_id)
        return "Permanently blocked"
    elif severity == "High":
        db_block_ip(ip, severity, site_id=site_id)
        return "Temporarily blocked (24 h)"
    else:
        return "Monitoring"


def is_blocked(ip: str, site_id: str = "local") -> bool:
    return db_is_blocked(ip, site_id=site_id)


def adaptive_action(ip: str, attack: str, severity: str, site_id: str = "local") -> str:
    db_add_history(ip, attack, site_id=site_id)
    count = db_get_history_count(ip, site_id=site_id)
    if count >= 5:
        db_block_ip(ip, "Critical", site_id=site_id)
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
    "AU": "Australia", "CA": "Canada", "IT": "Italy", "ES": "Spain",
    "NL": "Netherlands", "SE": "Sweden", "PL": "Poland", "RO": "Romania",
    "HK": "Hong Kong", "SG": "Singapore", "TH": "Thailand", "PH": "Philippines",
}

def _country_name(code: str) -> str:
    return _CC_TO_NAME.get((code or "").upper(), code or "Unknown")

# ── Real-Time GeoIP Engine (ipinfo.io — no API key needed for basic use) ────
_geoip_cache: dict = {}       # ip → {country, country_name, city, org, region, loc}
_geoip_lock = threading.Lock()

_CC_TO_FLAG = {
    "CN":"🇨🇳","RU":"🇷🇺","US":"🇺🇸","BR":"🇧🇷","IN":"🇮🇳","DE":"🇩🇪","KP":"🇰🇵","IR":"🇮🇷",
    "UA":"🇺🇦","NG":"🇳🇬","FR":"🇫🇷","GB":"🇬🇧","JP":"🇯🇵","KR":"🇰🇷","PK":"🇵🇰",
    "BD":"🇧🇩","ID":"🇮🇩","VN":"🇻🇳","TR":"🇹🇷","MX":"🇲🇽","AU":"🇦🇺","CA":"🇨🇦",
    "NL":"🇳🇱","SE":"🇸🇪","PL":"🇵🇱","RO":"🇷🇴","HK":"🇭🇰","SG":"🇸🇬","TH":"🇹🇭",
}

def _geoip_fetch_async(ip: str) -> None:
    """Background thread: fetch GeoIP from ipinfo.io and cache it."""
    if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "0.0.0")):
        with _geoip_lock:
            _geoip_cache[ip] = {"country": "LOCAL", "city": "localhost", "org": "Private", "region": "", "country_name": "Local", "flag": "🏠", "loc": "0,0"}
        return
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=3) as r:
            d = _json.loads(r.read())
        cc = d.get("country", "") or ""
        with _geoip_lock:
            _geoip_cache[ip] = {
                "country":      cc,
                "country_name": _CC_TO_NAME.get(cc.upper(), cc or "Unknown"),
                "flag":         _CC_TO_FLAG.get(cc.upper(), "🌐"),
                "city":         d.get("city", ""),
                "region":       d.get("region", ""),
                "org":          d.get("org", ""),   # e.g. "AS12345 Contabo GmbH"
                "loc":          d.get("loc", "0,0"),
                "timezone":     d.get("timezone", ""),
            }
    except Exception:
        with _geoip_lock:
            _geoip_cache[ip] = {}

def get_geoip(ip: str) -> dict:
    """Return GeoIP dict for an IP. Triggers background fetch if not cached."""
    with _geoip_lock:
        cached = _geoip_cache.get(ip)
    if cached is not None:
        return cached
    threading.Thread(target=_geoip_fetch_async, args=(ip,), daemon=True).start()
    return {}  # Will be populated within ~1-2 seconds



def serialize_sites_for_response(sites: list[dict], include_credentials: bool = False) -> list[dict]:
    """Attach per-site metrics while respecting tenant visibility."""
    result = []
    with get_db() as conn:
        for site in sites:
            count = conn.execute(
                "SELECT COUNT(*) FROM attack_log WHERE site_id = ?",
                (site["id"],),
            ).fetchone()[0]
            attacks = conn.execute(
                "SELECT COUNT(*) FROM attack_log WHERE site_id = ? AND severity != 'None'",
                (site["id"],),
            ).fetchone()[0]
            item = {
                "id":            site["id"],
                "name":          site["name"],
                "url":           site["url"],
                "created_at":    site["created_at"],
                "total_events":  count,
                "total_attacks": attacks,
            }
            if include_credentials:
                item["api_key"] = site["api_key"]
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# 5. Auth Routes
# ---------------------------------------------------------------------------

@app.route("/auth/login", methods=["GET", "POST"])
def auth_login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "").encode()
        user_data = db_get_user_by_email(email)
        if not user_data or not user_data.get("password_hash"):
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth_login"))
        if not bcrypt.checkpw(password, user_data["password_hash"].encode()):
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth_login"))
        user = User(user_data)
        login_user(user, remember=True)
        # If no site linked yet, go to authorization page
        if not user.site_id:
            flash(f"Welcome back, {user.name}! Please complete authorization.", "success")
            return redirect(url_for("auth_authorize"))
        flash(f"Welcome back, {user.name}! 👋", "success")
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/auth/signup", methods=["GET", "POST"])
def auth_signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        first  = request.form.get("first_name", "").strip()
        last   = request.form.get("last_name",  "").strip()
        name   = f"{first} {last}".strip() or first
        email  = request.form.get("email", "").lower().strip()
        pwd    = request.form.get("password", "")
        cpwd   = request.form.get("confirm_password", "")

        if not name or not email or not pwd:
            flash("All fields are required.", "error")
            return redirect(url_for("auth_signup"))
        if len(pwd) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("auth_signup"))
        if pwd != cpwd:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth_signup"))
        if db_get_user_by_email(email):
            flash("An account with this email already exists.", "error")
            return redirect(url_for("auth_signup"))

        # Create account without site_id — user will authorize on next page
        pwd_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
        uid = db_create_user(name, email, pwd_hash)  # site_id stays None
        if not uid:
            flash("Could not create account. Please try again.", "error")
            return redirect(url_for("auth_signup"))

        user_data = db_get_user_by_id(uid)
        login_user(User(user_data), remember=True)
        flash(f"Account created! Welcome, {name}. Now link your organisation.", "success")
        return redirect(url_for("auth_authorize"))  # Go to authorization step
    return render_template("signup.html")


@app.route("/auth/authorize", methods=["GET", "POST"])
@login_required
def auth_authorize():
    """Step 2 after registration: link account to a monitored site via Site ID + API Key."""
    if current_user.site_id:     # Already authorized
        return redirect(url_for("index"))
    if request.method == "POST":
        site_id_input = request.form.get("site_id", "").strip().lower()
        api_key_input = request.form.get("api_key",  "").strip()
        if not site_id_input or not api_key_input:
            flash("Both Site ID and API Key are required.", "error")
            return redirect(url_for("auth_authorize"))
        if not db_validate_api_key(site_id_input, api_key_input):
            flash("Invalid Site ID or API Key — please check and try again.", "error")
            return redirect(url_for("auth_authorize"))
        if db_update_user_site(current_user.id, site_id_input):
            user_data = db_get_user_by_id(current_user.id)
            login_user(User(user_data), remember=True)  # reload with updated site_id
            flash(f"✅ Authorized! Linked to site '{site_id_input}'.", "success")
            return redirect(url_for("index"))
        flash("Authorization failed. Please try again.", "error")
        return redirect(url_for("auth_authorize"))
    return render_template("authorize.html")


@app.route("/auth/skip-authorize")
@login_required
def auth_skip_authorize():
    """SOC Admin skips site authorization — gains access to all sites."""
    flash("🛡️ SOC Admin mode — you have full access to all monitored sites.", "success")
    return redirect(url_for("index"))


@app.route("/auth/logout")
@login_required
def auth_logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth_login"))


# ---------------------------------------------------------------------------
# 6. Main Routes (protected)
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Serve the SOC dashboard UI for authenticated users, otherwise show login."""
    if not current_user.is_authenticated:
        return redirect(url_for("auth_login"))
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    """Serve a favicon to avoid browser 404 noise."""
    return send_from_directory(STATIC_DIR, "favicon.ico")


@app.route("/embed", methods=["GET"])
@login_required
def embed():
    """Serve the agent embed instructions page."""
    return send_from_directory(STATIC_DIR, "embed.html")


@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({"status": "ok", "message": "Website Running Securely"}), 200


@app.route("/api/me", methods=["GET"])
@login_required
def api_me():
    """Return current logged-in user info for the dashboard header."""
    return jsonify({
        "id":           current_user.id,
        "name":         current_user.name,
        "email":        current_user.email,
        "role":         current_user.role,
        "site_id":      current_user.site_id,
        "is_admin":     is_admin_user(),
        "access_scope": "all-sites" if is_admin_user() else (current_user.site_id or "unassigned"),
    }), 200



# ---- Original login endpoint (unchanged) ----

@app.route("/login", methods=["POST"])
def login():
    ip   = get_client_ip()
    data = request.get_json(silent=True) or {}

    if is_blocked(ip, site_id="local"):
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
        action      = auto_block(ip, severity, site_id="local")
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
    adaptive_msg= adaptive_action(ip, attack_type, severity, site_id="local")
    block_action= auto_block(ip, severity, site_id="local")
    action      = block_action if block_action != "Monitoring" else adaptive_msg

    log_attack(ip, attack_type, severity)
    return jsonify({
        "ip": ip, "attack": attack_type, "severity": severity,
        "action": action, "message": response,
    }), 200


# ---- Dashboard ----

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """
    Return dashboard data.
    - Admin users: return all tenant data.
    - Company users: return only their linked site data.
    """
    if is_admin_user():
        return jsonify({
            "total_events": db_get_total_events(),
            "blocked_ips":  db_get_blocked_ips(),
            "attack_log":   db_get_all_logs(),
            "site_filter":  None,
        }), 200

    user_site = getattr(current_user, "site_id", None)
    if not user_site:
        return jsonify({"error": "Your account is not linked to any company site."}), 403

    logs = db_get_logs_by_site(user_site, limit=500)
    return jsonify({
        "total_events": len(logs),
        "blocked_ips":  db_get_blocked_ips(site_id=user_site),
        "attack_log":   logs,
        "site_filter":  user_site,
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
    ip      = data.get("ip") or get_client_ip()

    # Strict API key validation — no exceptions, no demo bypass
    if not site_id or not api_key:
        return jsonify({"error": "site_id and api_key are required"}), 400
    if not db_validate_api_key(site_id, api_key):
        return jsonify({"error": "Invalid site_id or api_key"}), 401

    method     = data.get("method", "GET")
    path       = data.get("path", "/")
    user_agent = data.get("user_agent", "")
    referer    = data.get("referer", "")
    bytes_in   = int(data.get("bytes_in", 0) or 0)

    # ── Real-Time GeoIP lookup ───────────────────────────────────────────────
    geo = get_geoip(ip)   # non-blocking (cached or triggers background thread)
    country = data.get("country") or geo.get("country", "")
    city    = data.get("city")    or geo.get("city", "")
    asn     = data.get("asn")     or geo.get("org", "")   # ASN + ISP name

    # --- Blocked IP check ---
    if is_blocked(ip, site_id=site_id):
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
    adaptive_msg = adaptive_action(ip, attack_type, severity, site_id=site_id)
    block_action = auto_block(ip, severity, site_id=site_id)
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

    geo_full = {**geo}  # full GeoIP for response

    return jsonify({
        "ip":           ip,
        "attack":       attack_type,
        "severity":     severity,
        "action":       action,
        "site_id":      site_id,
        "country":      country or geo_full.get("country", "Unknown"),
        "country_name": geo_full.get("country_name") or _country_name(country),
        "flag":         geo_full.get("flag", "🌐"),
        "city":         city or geo_full.get("city", ""),
        "region":       geo_full.get("region", ""),
        "org":          asn or geo_full.get("org", ""),
        "loc":          geo_full.get("loc", ""),
    }), 200


# ---- Sites registry (public — api_key NEVER exposed) ----

@app.route("/api/sites", methods=["GET"])
@login_required
def api_sites():
    """
    Return monitored sites for the logged-in tenant scope.
    - Company user: returns only their own site.
    - Admin user: returns all sites.
    """
    include_credentials = request.args.get("include_credentials", "").lower() in {"1", "true", "yes"}
    sites = db_get_sites()
    if is_admin_user():
        return jsonify(serialize_sites_for_response(sites, include_credentials=include_credentials)), 200

    user_site = getattr(current_user, "site_id", None)
    if not user_site:
        return jsonify({"error": "Your account is not linked to any company site."}), 403

    sites = [site for site in sites if site["id"] == user_site]
    return jsonify(serialize_sites_for_response(sites, include_credentials=include_credentials)), 200


# ---- Admin-only: full site listing with api_keys ----

@app.route("/api/admin/sites", methods=["GET"])
@login_required
def api_admin_sites():
    """Admin-only site inventory, including API keys."""
    if not is_admin_user():
        return jsonify({"error": "Admin access required"}), 403
    return jsonify(serialize_sites_for_response(db_get_sites(), include_credentials=True)), 200


# ---- Agent logs by site (api_key required — site sees ONLY its own data) ----

@app.route("/api/agent/logs", methods=["GET"])
@login_required
def api_agent_logs():
    """
    Return attack logs for a site.
    - Company users can only access their own linked site.
    - Admin users can access any site.
    """
    site_id = request.args.get("site_id", "")
    if not site_id:
        return jsonify({"error": "site_id required"}), 400

    if not is_admin_user():
        user_site = getattr(current_user, "site_id", None)
        if not user_site:
            return jsonify({"error": "Your account is not linked to any company site."}), 403
        if site_id != user_site:
            return jsonify({"error": "Access denied — you can only access your own site's logs"}), 403

    logs = db_get_logs_by_site(site_id, limit=200)
    return jsonify({
        "site_id":    site_id,
        "total":      len(logs),
        "attack_log": logs,
    }), 200


# ---- Widget API (API key auth — no login required) ----

@app.route("/api/widget/logs", methods=["GET"])
def api_widget_logs():
    """
    Return attack logs for a site using API key authentication.
    This endpoint is designed for the embeddable widget.
    Headers required: X-Site-ID, X-API-Key
    """
    site_id = request.args.get("site_id") or request.headers.get("X-Site-ID", "")
    api_key = request.headers.get("X-API-Key", "")

    if not site_id or not api_key:
        return jsonify({"error": "site_id and api_key are required"}), 400

    if not db_validate_api_key(site_id, api_key):
        return jsonify({"error": "Invalid site_id or api_key"}), 401

    logs = db_get_logs_by_site(site_id, limit=50)
    blocked = db_get_blocked_ips(site_id=site_id)

    return jsonify({
        "site_id":    site_id,
        "total":      len(logs),
        "attack_log": logs,
        "blocked_ips": blocked,
    }), 200


# ---- Return API key for the logged-in user's own site ----

@app.route("/api/my-site-key", methods=["GET"])
@login_required
def api_my_site_key():
    """Return the API key for the current user's linked site. Requires the user to be linked."""
    user_site = getattr(current_user, "site_id", None)
    if not user_site:
        return jsonify({"error": "Your account is not linked to any site."}), 403
    sites = db_get_sites()
    site  = next((s for s in sites if s["id"] == user_site), None)
    if not site:
        return jsonify({"error": "Site not found."}), 404
    return jsonify({"site_id": user_site, "api_key": site.get("api_key", "")}), 200


# ---- Real-time live attack details for monitored sites ----

@app.route("/api/live-attacks", methods=["GET"])
@login_required
def api_live_attacks():
    """
    Returns recent attack events enriched with full attacker details including GeoIP.
    Used by the SOC dashboard "Site Alerts" panel.
    """
    site_id = request.args.get("site_id", "")
    limit   = min(int(request.args.get("limit", 20)), 100)
    since   = request.args.get("since", "")  # ISO timestamp filter

    # Scope to user's site unless admin
    if not is_admin_user():
        user_site = getattr(current_user, "site_id", None)
        if not user_site:
            return jsonify({"attacks": []}), 200
        site_id = user_site  # force to own site

    with get_db() as conn:
        query = """
            SELECT id, ip, attack, severity, timestamp, blocked, site_id,
                   user_agent, method, path, referer, country, city, asn, bytes_in
            FROM attack_log
            WHERE severity != 'None'
        """
        params: list = []
        if site_id:
            query  += " AND site_id = ?"
            params.append(site_id)
        if since:
            query  += " AND timestamp > ?"
            params.append(since)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()

    results = []
    for row in rows:
        d   = dict(row)
        ip  = d.get("ip", "")
        cc  = d.get("country", "") or ""
        # Enrich with cached GeoIP (if available)
        geo = get_geoip(ip)  # non-blocking
        country_name = geo.get("country_name") or _country_name(cc) or "Unknown"
        flag         = geo.get("flag") or _CC_TO_FLAG.get(cc.upper(), "🌐")
        city         = d.get("city") or geo.get("city", "")
        region       = geo.get("region", "")
        org          = d.get("asn")  or geo.get("org", "")
        loc          = geo.get("loc", "")
        lat, lon     = (loc.split(",") + ["", ""])[:2] if loc else ("", "")

        results.append({
            **d,
            "country_name": country_name,
            "flag":         flag,
            "city":         city,
            "region":       region,
            "org":          org,
            "lat":          lat,
            "lon":          lon,
            "is_blocked":   bool(d.get("blocked")),
        })

    return jsonify({"attacks": results, "total": len(results)}), 200


# ---------------------------------------------------------------------------
# 6. Entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
