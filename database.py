# =============================================================================
# database.py — SQLite Persistence Layer
# Stores attack logs, blocked IPs, attack history, sites registry
# =============================================================================

import os
import sqlite3
import time
import secrets
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_attacks.db")


@contextmanager
def get_db():
    """Thread-safe database connection context manager."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they don't exist; migrate existing tables if needed."""
    with get_db() as conn:
        # Step 1: Core tables (no site_id index yet)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS attack_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                attack      TEXT NOT NULL,
                severity    TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                created_at  REAL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip          TEXT PRIMARY KEY,
                reason      TEXT NOT NULL DEFAULT 'auto',
                block_type  TEXT NOT NULL DEFAULT 'permanent',
                expires_at  REAL,
                blocked_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS attack_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                attack      TEXT NOT NULL,
                recorded_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS failed_attempts (
                ip          TEXT PRIMARY KEY,
                count       INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS sites (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                url         TEXT NOT NULL,
                api_key     TEXT NOT NULL UNIQUE,
                created_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_log_ip       ON attack_log(ip);
            CREATE INDEX IF NOT EXISTS idx_log_severity ON attack_log(severity);
            CREATE INDEX IF NOT EXISTS idx_history_ip   ON attack_history(ip);
        """)

        # Step 2: Migrate — add new columns if not present
        cols = [r[1] for r in conn.execute("PRAGMA table_info(attack_log)").fetchall()]
        for col, col_type, default in [
            ("site_id",    "TEXT",    "'local'"),
            ("user_agent", "TEXT",    "NULL"),
            ("method",     "TEXT",    "NULL"),
            ("path",       "TEXT",    "NULL"),
            ("referer",    "TEXT",    "NULL"),
            ("country",    "TEXT",    "NULL"),
            ("city",       "TEXT",    "NULL"),
            ("asn",        "TEXT",    "NULL"),
            ("bytes_in",   "INTEGER", "0"),
        ]:
            if col not in cols:
                conn.execute(
                    f"ALTER TABLE attack_log ADD COLUMN {col} {col_type} DEFAULT {default}"
                )

        # Step 3: Now safe to create site_id index
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_log_site ON attack_log(site_id)"
        )

    print(f"[DB] Database initialized at {DB_PATH}")



# ---------------------------------------------------------------------------
# Attack Log
# ---------------------------------------------------------------------------

def db_log_attack(ip: str, attack: str, severity: str, timestamp: str = None,
                  site_id: str = "local", user_agent: str = None, method: str = None,
                  path: str = None, referer: str = None, country: str = None,
                  city: str = None, asn: str = None, bytes_in: int = 0):
    """Insert an attack event into the database."""
    ts = timestamp or (datetime.utcnow().isoformat() + "Z")
    with get_db() as conn:
        conn.execute(
            """INSERT INTO attack_log
               (ip, attack, severity, timestamp, site_id, user_agent, method, path,
                referer, country, city, asn, bytes_in)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ip, attack, severity, ts, site_id, user_agent, method, path,
             referer, country, city, asn, bytes_in),
        )


def db_get_all_logs() -> list[dict]:
    """Return all attack log entries ordered by id."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT ip, attack, severity, timestamp, site_id,
                      user_agent, method, path, referer, country, city, asn, bytes_in
               FROM attack_log ORDER BY id"""
        ).fetchall()
    return [dict(r) for r in rows]


def db_get_total_events() -> int:
    """Return the total number of logged events."""
    with get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM attack_log").fetchone()[0]


def db_get_logs_by_site(site_id: str, limit: int = 200) -> list[dict]:
    """Return attack log entries for a specific monitored site."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT ip, attack, severity, timestamp, site_id,
                      user_agent, method, path, referer, country, city, asn, bytes_in
               FROM attack_log WHERE site_id = ?
               ORDER BY id DESC LIMIT ?""",
            (site_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------

def db_block_ip(ip: str, severity: str):
    """Block an IP based on severity."""
    if severity == "Critical":
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, reason, block_type, expires_at) VALUES (?, ?, 'permanent', NULL)",
                (ip, f"auto-blocked ({severity})"),
            )
    elif severity == "High":
        expires = time.time() + 86_400
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, reason, block_type, expires_at) VALUES (?, ?, 'temporary', ?)",
                (ip, f"auto-blocked ({severity})", expires),
            )


def db_is_blocked(ip: str) -> bool:
    """Check if IP is currently blocked; auto-lift expired temp blocks."""
    with get_db() as conn:
        row = conn.execute("SELECT block_type, expires_at FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            return False
        if row["block_type"] == "temporary" and row["expires_at"] and time.time() > row["expires_at"]:
            conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            return False
        return True


def db_get_blocked_ips() -> list[str]:
    """Return all currently blocked IPs (removes expired ones first)."""
    with get_db() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE block_type = 'temporary' AND expires_at < ?", (time.time(),))
        rows = conn.execute("SELECT ip FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return [r["ip"] for r in rows]


# ---------------------------------------------------------------------------
# Attack History (for adaptive security)
# ---------------------------------------------------------------------------

def db_add_history(ip: str, attack: str):
    """Record an attack in the per-IP history."""
    with get_db() as conn:
        conn.execute("INSERT INTO attack_history (ip, attack) VALUES (?, ?)", (ip, attack))


def db_get_history_count(ip: str) -> int:
    """Return how many attacks this IP has triggered."""
    with get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM attack_history WHERE ip = ?", (ip,)).fetchone()[0]


# ---------------------------------------------------------------------------
# Failed Attempts (brute-force tracking)
# ---------------------------------------------------------------------------

def db_increment_failed(ip: str) -> int:
    """Increment failed login count for an IP; return new count."""
    with get_db() as conn:
        conn.execute(
            "INSERT INTO failed_attempts (ip, count) VALUES (?, 1) "
            "ON CONFLICT(ip) DO UPDATE SET count = count + 1, last_attempt = datetime('now')",
            (ip,),
        )
        row = conn.execute("SELECT count FROM failed_attempts WHERE ip = ?", (ip,)).fetchone()
        return row["count"]


def db_get_failed_count(ip: str) -> int:
    """Return the current failed login count for an IP."""
    with get_db() as conn:
        row = conn.execute("SELECT count FROM failed_attempts WHERE ip = ?", (ip,)).fetchone()
        return row["count"] if row else 0


# ---------------------------------------------------------------------------
# Sites Registry
# ---------------------------------------------------------------------------

def db_register_site(site_id: str, name: str, url: str) -> str:
    """Register a new monitored site; return its generated API key."""
    api_key = secrets.token_hex(24)
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO sites (id, name, url, api_key) VALUES (?, ?, ?, ?)",
            (site_id, name, url, api_key),
        )
        row = conn.execute("SELECT api_key FROM sites WHERE id = ?", (site_id,)).fetchone()
    return row["api_key"]


def db_get_sites() -> list[dict]:
    """Return all registered monitored sites."""
    with get_db() as conn:
        rows = conn.execute("SELECT id, name, url, api_key, created_at FROM sites ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]


def db_validate_api_key(site_id: str, api_key: str) -> bool:
    """Return True if the api_key matches the registered site."""
    with get_db() as conn:
        row = conn.execute("SELECT 1 FROM sites WHERE id = ? AND api_key = ?", (site_id, api_key)).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Seed data (only if DB is empty)
# ---------------------------------------------------------------------------

def seed_demo_data():
    """Populate the database with realistic demo events if it's empty."""
    if db_get_total_events() > 0:
        print("[DB] Database already has data — skipping seed.")
        # Seed demo sites if missing
        _seed_demo_sites()
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
        ts      = (now - __import__("datetime").timedelta(seconds=(len(SEED_EVENTS) - i) * 12)).isoformat() + "Z"
        cidx    = rng.randrange(len(SEED_COUNTRIES))
        db_log_attack(
            ip, atk, sev, ts,
            site_id    = rng.choice(SEED_SITES),
            user_agent = rng.choice(SEED_UAS),
            method     = rng.choice(SEED_METHODS),
            path       = rng.choice(SEED_PATHS),
            referer    = rng.choice(["", "http://evil.ru", "https://pastebin.com", ""]),
            country    = SEED_COUNTRIES[cidx],
            city       = SEED_CITIES[cidx],
            asn        = rng.choice(SEED_ASNS),
            bytes_in   = rng.randint(64, 65535),
        )
        db_add_history(ip, atk)
        if sev in ("Critical", "High"):
            db_block_ip(ip, sev)

    print(f"[DB] Seeded {len(SEED_EVENTS)} demo events.")
    _seed_demo_sites()


def _seed_demo_sites():
    """Register demo monitoring sites if not already present."""
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    if count > 0:
        return
    db_register_site("gov-portal",    "Government Portal",    "https://gov.example.in")
    db_register_site("finance-dept",  "Finance Department",   "https://finance.example.in")
    db_register_site("local",         "Local SOC Backend",    "http://127.0.0.1:5000")
    print("[DB] Seeded 3 demo monitored sites.")
