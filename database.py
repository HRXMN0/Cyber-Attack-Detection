# =============================================================================
# database.py — Supabase Persistence Layer
# Stores attack logs, blocked IPs, attack history, sites registry
# =============================================================================

import os
import time
import secrets
from datetime import datetime

import bcrypt
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

# Initialize Supabase client
SUPABASE_URL: str = os.environ.get("SUPABASE_URL")
SUPABASE_KEY: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def init_db():
    """Check Supabase connection and handle optional setup."""
    print("[DB] Initializing Supabase database connection...")
    # Optionally checking if we can query 'sites' table
    try:
        supabase.table('sites').select('id').limit(1).execute()
        print("[DB] Configured safely and connected to Supabase.")
    except Exception as e:
        print("[DB] Warning: connecting to Supabase tables, ensure schema is applied. Errored:", e)


# For backwards compatibility with parts of the app that did 'with get_db() as conn:' 
# We'll no longer use it, but keeping the signature removed forces us to fix app.py!


# ---------------------------------------------------------------------------
# Attack Log
# ---------------------------------------------------------------------------

def db_log_attack(ip: str, attack: str, severity: str, timestamp: str = None,
                  site_id: str = "local", user_agent: str = None, method: str = None,
                  path: str = None, referer: str = None, country: str = None,
                  city: str = None, asn: str = None, bytes_in: int = 0):
    """Insert an attack event into the database."""
    ts = timestamp or (datetime.utcnow().isoformat() + "Z")
    data = {
        "ip": ip, "attack": attack, "severity": severity, "timestamp": ts,
        "site_id": site_id, "user_agent": user_agent, "method": method,
        "path": path, "referer": referer, "country": country,
        "city": city, "asn": asn, "bytes_in": bytes_in
    }
    supabase.table("attack_log").insert(data).execute()


def db_get_all_logs() -> list[dict]:
    """Return all attack log entries ordered by id."""
    res = supabase.table("attack_log").select("*").order("id").execute()
    return res.data


def db_get_total_events() -> int:
    """Return the total number of logged events."""
    res = supabase.table("attack_log").select("*", count="exact", head=True).execute()
    return res.count or 0


def db_get_logs_by_site(site_id: str, limit: int = 200) -> list[dict]:
    """Return attack log entries for a specific monitored site."""
    res = supabase.table("attack_log").select("*").eq("site_id", site_id).order("id", desc=True).limit(limit).execute()
    return res.data


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------

def db_block_ip(ip: str, severity: str, site_id: str = "local"):
    """Block an IP based on severity."""
    if severity == "Critical":
        data = {
            "ip": ip, "site_id": site_id, "reason": f"auto-blocked ({severity})",
            "block_type": "permanent", "expires_at": None, "blocked_at": datetime.utcnow().isoformat() + "Z"
        }
        supabase.table("site_blocked_ips").upsert(data, on_conflict="ip,site_id").execute()
    elif severity == "High":
        expires = time.time() + 86_400
        data = {
            "ip": ip, "site_id": site_id, "reason": f"auto-blocked ({severity})",
            "block_type": "temporary", "expires_at": expires, "blocked_at": datetime.utcnow().isoformat() + "Z"
        }
        supabase.table("site_blocked_ips").upsert(data, on_conflict="ip,site_id").execute()


def db_is_blocked(ip: str, site_id: str = "local") -> bool:
    """Check if IP is currently blocked; auto-lift expired temp blocks."""
    res = supabase.table("site_blocked_ips").select("block_type, expires_at").eq("ip", ip).eq("site_id", site_id).execute()
    if not res.data:
        return False
    row = res.data[0]
    if row["block_type"] == "temporary" and row["expires_at"] and time.time() > row["expires_at"]:
        supabase.table("site_blocked_ips").delete().eq("ip", ip).eq("site_id", site_id).execute()
        return False
    return True


def db_get_blocked_ips(site_id: str = None) -> list[str]:
    """Return blocked IPs globally or for a single site."""
    # Delete expired
    supabase.table("site_blocked_ips").delete().eq("block_type", "temporary").lt("expires_at", time.time()).execute()
    
    if site_id:
        res = supabase.table("site_blocked_ips").select("ip").eq("site_id", site_id).order("blocked_at", desc=True).execute()
    else:
        res = supabase.table("site_blocked_ips").select("ip").execute()
    
    # Needs distinct ip logic
    return list(set([r["ip"] for r in res.data]))


# ---------------------------------------------------------------------------
# Attack History (for adaptive security)
# ---------------------------------------------------------------------------

def db_add_history(ip: str, attack: str, site_id: str = "local"):
    """Record an attack in the per-IP history."""
    supabase.table("attack_history").insert({"ip": ip, "attack": attack, "site_id": site_id}).execute()


def db_get_history_count(ip: str, site_id: str = "local") -> int:
    """Return how many attacks this IP has triggered for a given site."""
    res = supabase.table("attack_history").select("*", count="exact", head=True).eq("ip", ip).eq("site_id", site_id).execute()
    return res.count or 0


# ---------------------------------------------------------------------------
# Failed Attempts (brute-force tracking)
# ---------------------------------------------------------------------------

def db_increment_failed(ip: str) -> int:
    """Increment failed login count for an IP; return new count."""
    res = supabase.table("failed_attempts").select("count").eq("ip", ip).execute()
    if res.data:
        new_count = res.data[0]["count"] + 1
        supabase.table("failed_attempts").update({"count": new_count, "last_attempt": datetime.utcnow().isoformat() + "Z"}).eq("ip", ip).execute()
        return new_count
    else:
        supabase.table("failed_attempts").insert({"ip": ip, "count": 1}).execute()
        return 1


def db_get_failed_count(ip: str) -> int:
    """Return the current failed login count for an IP."""
    res = supabase.table("failed_attempts").select("count").eq("ip", ip).execute()
    return res.data[0]["count"] if res.data else 0


# ---------------------------------------------------------------------------
# Sites Registry
# ---------------------------------------------------------------------------

def db_register_site(site_id: str, name: str, url: str) -> str:
    """Register a new monitored site; return its generated API key."""
    res = supabase.table("sites").select("api_key").eq("id", site_id).execute()
    if res.data:
        return res.data[0]["api_key"]
    
    api_key = secrets.token_hex(24)
    supabase.table("sites").insert({"id": site_id, "name": name, "url": url, "api_key": api_key}).execute()
    return api_key


def db_get_sites() -> list[dict]:
    """Return all registered monitored sites."""
    res = supabase.table("sites").select("id, name, url, api_key, created_at").order("created_at").execute()
    return res.data


def db_validate_api_key(site_id: str, api_key: str) -> bool:
    """Return True if the api_key matches the registered site."""
    res = supabase.table("sites").select("id").eq("id", site_id).eq("api_key", api_key).execute()
    return len(res.data) > 0


# ---------------------------------------------------------------------------
# Seed data (only if DB is empty)
# ---------------------------------------------------------------------------

def seed_demo_data():
    """Populate the database with realistic demo sites, users, and events."""
    try:
        _seed_demo_sites()
        _seed_demo_users()
    except Exception as e:
        print("[DB] Warning: Could not seed demo data. Have you applied the SQL schema to Supabase? Error:", e)
        return

    if db_get_total_events() > 0:
        print("[DB] Database already has data — skipping event seed.")
        return

    import random as rng
    from datetime import timedelta

    SEED_IPS = [
        "192.168.1.105", "10.0.0.47", "172.16.8.3", "45.33.32.156",
        "103.21.244.15", "198.51.100.22", "91.189.88.142", "185.220.101.6",
        "77.247.181.163", "209.141.55.26", "23.129.64.210", "162.247.74.7",
        "104.244.76.13", "51.15.43.205", "89.248.167.131", "193.118.53.202",
        "45.155.205.39", "141.98.11.70", "178.128.23.9", "64.62.197.152",
    ]
    SEED_EVENTS = [
        ("normal", "None"), ("normal", "None"), ("normal", "None"),
        ("normal", "None"), ("normal", "None"),
        ("portsweep", "Medium"), ("nmap", "Medium"), ("ipsweep", "Medium"),
        ("satan", "Medium"), ("neptune", "Critical"), ("neptune", "Critical"),
        ("smurf", "Critical"), ("back", "High"), ("teardrop", "High"),
        ("guess_passwd", "High"), ("ftp_write", "High"),
        ("buffer_overflow", "Critical"), ("rootkit", "Critical"),
        ("bruteforce", "Critical"), ("warezclient", "Medium"),
        ("warezmaster", "High"), ("phf", "Medium"), ("normal", "None"),
        ("pod", "High"), ("land", "High"), ("mscan", "Medium"),
        ("saint", "Medium"), ("snmpguess", "High"), ("httptunnel", "High"),
        ("normal", "None"),
    ]

    SEED_PATHS = ["/", "/login", "/admin", "/api/data", "/wp-admin", "/.env", "/admin/login",
                  "/static/app.js", "/api/users", "/phpmyadmin"]
    SEED_UAS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "python-requests/2.28.1", "Nmap/7.93", "sqlmap/1.7", "curl/7.85.0",
        "Go-http-client/1.1", "Nikto/2.1.6", "masscan/1.3.2",
    ]
    SEED_COUNTRIES = ["CN", "RU", "US", "BR", "IR", "KP", "NG", "UA"]
    SEED_CITIES    = ["Beijing", "Moscow", "New York", "São Paulo", "Tehran", "Pyongyang", "Lagos", "Kyiv"]
    SEED_ASNS      = ["AS4134", "AS8359", "AS15169", "AS7922", "AS44050", "AS24940"]
    SEED_METHODS   = ["GET", "GET", "GET", "POST", "POST", "PUT", "DELETE"]
    SEED_SITES     = ["gov-portal", "finance-dept", "local"]

    now = datetime.utcnow()
    for i, (atk, sev) in enumerate(SEED_EVENTS):
        ip      = rng.choice(SEED_IPS)
        ts      = (now - timedelta(seconds=(len(SEED_EVENTS) - i) * 12)).isoformat() + "Z"
        cidx    = rng.randrange(len(SEED_COUNTRIES))
        site_id = rng.choice(SEED_SITES)
        db_log_attack(
            ip, atk, sev, ts,
            site_id    = site_id,
            user_agent = rng.choice(SEED_UAS),
            method     = rng.choice(SEED_METHODS),
            path       = rng.choice(SEED_PATHS),
            referer    = rng.choice(["", "http://evil.ru", "https://pastebin.com", ""]),
            country    = SEED_COUNTRIES[cidx],
            city       = SEED_CITIES[cidx],
            asn        = rng.choice(SEED_ASNS),
            bytes_in   = rng.randint(64, 65535),
        )
        db_add_history(ip, atk, site_id=site_id)
        if sev in ("Critical", "High"):
            db_block_ip(ip, sev, site_id=site_id)

    print(f"[DB] Seeded {len(SEED_EVENTS)} demo events.")


def _seed_demo_sites():
    """Register demo monitoring sites if not already present."""
    res = supabase.table("sites").select("*", count="exact", head=True).execute()
    if res.count and res.count > 0:
        return
    db_register_site("gov-portal",    "Government Portal",    "https://gov.example.in")
    db_register_site("finance-dept",  "Finance Department",   "https://finance.example.in")
    db_register_site("local",         "Local SOC Backend",    "http://127.0.0.1:5000")
    print("[DB] Seeded 3 demo monitored sites.")


def _seed_demo_users():
    """Create demo accounts for quick local testing if they do not exist."""
    demo_users = [
        {
            "name": "SOC Admin",
            "email": "admin@soc.local",
            "password": "Admin@123",
            "role": "admin",
            "site_id": None,
        },
        {
            "name": "Gov Portal Analyst",
            "email": "analyst@gov.local",
            "password": "Analyst@123",
            "role": "analyst",
            "site_id": "gov-portal",
        },
        {
            "name": "Finance Analyst",
            "email": "analyst@finance.local",
            "password": "Analyst@123",
            "role": "analyst",
            "site_id": "finance-dept",
        },
    ]

    created = 0
    for user in demo_users:
        if db_get_user_by_email(user["email"]):
            continue
        password_hash = bcrypt.hashpw(user["password"].encode(), bcrypt.gensalt()).decode()
        user_id = db_create_user(
            user["name"],
            user["email"],
            password_hash,
            role=user["role"],
            site_id=user["site_id"],
        )
        if user_id:
            created += 1

    if created:
        print(f"[DB] Seeded {created} demo user account(s).")


# ---------------------------------------------------------------------------
# Users (Authentication)
# ---------------------------------------------------------------------------

def db_create_user(name: str, email: str, password_hash: str, role: str = "analyst", site_id: str = None) -> int | None:
    """Create a new user. Returns new user id, or None if email exists."""
    try:
        data = {"name": name, "email": email, "password_hash": password_hash, "role": role, "site_id": site_id}
        res = supabase.table("users").insert(data).execute()
        return res.data[0]["id"] if res.data else None
    except Exception:
        return None


def db_get_user_by_email(email: str) -> dict | None:
    """Fetch user dict by email, or None."""
    res = supabase.table("users").select("id, name, email, password_hash, role, site_id, created_at").eq("email", email.lower().strip()).execute()
    return res.data[0] if res.data else None


def db_get_user_by_id(user_id: int) -> dict | None:
    """Fetch user dict by primary key id, or None."""
    res = supabase.table("users").select("id, name, email, password_hash, role, site_id, created_at").eq("id", user_id).execute()
    return res.data[0] if res.data else None


def db_update_user_site(user_id: int, site_id: str | None) -> bool:
    """Update the site_id for a user (link or unlink). Returns True on success."""
    try:
        supabase.table("users").update({"site_id": site_id}).eq("id", user_id).execute()
        return True
    except Exception:
        return False
