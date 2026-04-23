# =============================================================================
# simulate.py — Real-Time Attack Simulation Script
#
# Sends multiple POST requests to the /login endpoint to simulate:
#   • Normal login attempts
#   • Brute-force attacks (> 5 failed attempts from same IP)
#   • ML-detected intrusion scenarios
#
# Run AFTER starting app.py:
#   python simulate.py
# =============================================================================

import json
import time
import requests

from database import db_get_sites

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL          = "http://127.0.0.1:5000"
LOGIN_URL         = f"{BASE_URL}/login"
AUTH_LOGIN_URL    = f"{BASE_URL}/auth/login"
DASH_URL          = f"{BASE_URL}/dashboard"
AGENT_REPORT_URL  = f"{BASE_URL}/api/agent/report"
DEMO_SITE_ID      = "gov-portal"

SEPARATOR  = "=" * 70
RUN_TAG    = int(time.time()) % 200


def scenario_ip(offset: int) -> str:
    """Return a semi-unique documentation-range IP per simulator run."""
    last_octet = ((RUN_TAG + offset) % 200) + 1
    return f"198.51.100.{last_octet}"


def pretty(data: dict) -> str:
    """Return a nicely formatted JSON string."""
    return json.dumps(data, indent=2)


def get_demo_site_credentials() -> tuple[str, str]:
    """Return seeded demo site credentials used by the website analyst account."""
    for site in db_get_sites():
        if site["id"] == DEMO_SITE_ID:
            return site["id"], site["api_key"]
    raise RuntimeError(f"Demo site '{DEMO_SITE_ID}' not found in database.")


def send_request(label: str, payload: dict, client_ip: str, delay: float = 2.0) -> None:
    """Send a single POST to /login and print the result."""
    print(f"\n[{label}]")
    print(f"  Client  : {client_ip}")
    print(f"  Payload : {payload}")
    headers = {"X-Forwarded-For": client_ip}
    try:
        resp = requests.post(LOGIN_URL, json=payload, headers=headers, timeout=5)
        print(f"  Status  : {resp.status_code}")
        print(f"  Response:\n{pretty(resp.json())}")
    except requests.exceptions.ConnectionError:
        print("  [ERROR] Cannot connect. Is app.py running?")
    time.sleep(delay)


# ---------------------------------------------------------------------------
# Simulation scenarios
# ---------------------------------------------------------------------------

def simulate_normal_login() -> None:
    """Simulate a successful / valid login attempt."""
    print(f"\n{SEPARATOR}")
    print(" SCENARIO 1 — Normal Login Attempt")
    print(SEPARATOR)
    send_request(
        label     = "Normal Login",
        payload   = {"username": "alice", "password": "Str0ng@Pass!"},
        client_ip = scenario_ip(10),
    )


def simulate_failed_logins(count: int = 3) -> None:
    """Simulate a few failed logins (below brute-force threshold)."""
    print(f"\n{SEPARATOR}")
    print(f" SCENARIO 2 — {count} Failed Login Attempts (below threshold)")
    print(SEPARATOR)
    for i in range(1, count + 1):
        send_request(
            label     = f"Failed Login #{i}",
            payload   = {"username": "bob", "password": ""},   # empty pw → failure
            client_ip = scenario_ip(20),
        )


def simulate_bruteforce(count: int = 8) -> None:
    """
    Simulate a brute-force attack by sending many login attempts
    with missing credentials, triggering the > 5 failed-attempt rule.
    """
    print(f"\n{SEPARATOR}")
    print(f" SCENARIO 3 — Brute-Force Attack ({count} rapid requests)")
    print(SEPARATOR)
    for i in range(1, count + 1):
        send_request(
            label     = f"Brute Force #{i}",
            payload   = {"username": "admin", "password": ""},
            client_ip = scenario_ip(66),
        )


def simulate_ml_detection() -> None:
    """
    Simulate ML-based detection by sending requests that mimic
    various network traffic patterns.
    """
    print(f"\n{SEPARATOR}")
    print(" SCENARIO 4 — ML-Based Intrusion Detection Simulation")
    print(SEPARATOR)

    # Each of these represents a different 'attacker' pattern
    payloads = [
        {"username": "user1", "password": "pass1", "hint": "port_scan_pattern"},
        {"username": "user2", "password": "pass2", "hint": "dos_pattern"},
        {"username": "user3", "password": "pass3", "hint": "r2l_pattern"},
    ]
    for p in payloads:
        hint = p.get("hint", "ml")
        test_ip_map = {
            "port_scan_pattern": scenario_ip(131),
            "dos_pattern": scenario_ip(132),
            "r2l_pattern": scenario_ip(133),
        }
        send_request(
            label="ML Prediction",
            payload=p,
            client_ip=test_ip_map.get(hint, "203.0.113.30"),
        )


def send_site_event(label: str, payload: dict, delay: float = 1.5) -> None:
    """Send telemetry to the tenant-scoped agent endpoint so it appears in the website UI."""
    site_id, api_key = get_demo_site_credentials()
    body = {
        "site_id": site_id,
        "api_key": api_key,
        **payload,
    }

    print(f"\n[{label}]")
    print(f"  Site    : {site_id}")
    print(f"  Payload : {body}")

    try:
        resp = requests.post(AGENT_REPORT_URL, json=body, timeout=5)
        print(f"  Status  : {resp.status_code}")
        print(f"  Response:\n{pretty(resp.json())}")
    except requests.exceptions.ConnectionError:
        print("  [ERROR] Cannot connect. Is app.py running?")
    time.sleep(delay)


def simulate_site_telemetry() -> None:
    """Send website-visible events to the gov-portal tenant for the analyst dashboard."""
    print(f"\n{SEPARATOR}")
    print(" SCENARIO 5 — Website-Visible Tenant Telemetry (gov-portal)")
    print(SEPARATOR)

    site_payloads = [
        {
            "ip": scenario_ip(150),
            "method": "GET",
            "path": "/admin/login",
            "user_agent": "python-requests/2.32.3",
            "referer": "",
            "bytes_in": 812,
            "country": "RU",
            "city": "Moscow",
            "asn": "AS8359",
        },
        {
            "ip": scenario_ip(151),
            "method": "POST",
            "path": "/api/auth",
            "user_agent": "sqlmap/1.8",
            "referer": "http://evil.ru",
            "bytes_in": 4096,
            "country": "CN",
            "city": "Beijing",
            "asn": "AS4134",
        },
        {
            "ip": scenario_ip(152),
            "method": "GET",
            "path": "/wp-admin",
            "user_agent": "Nmap/7.95",
            "referer": "",
            "bytes_in": 1200,
            "country": "IR",
            "city": "Tehran",
            "asn": "AS44050",
        },
        {
            "ip": scenario_ip(153),
            "method": "GET",
            "path": "/.env",
            "user_agent": "curl/8.8.0",
            "referer": "",
            "bytes_in": 640,
            "country": "KP",
            "city": "Pyongyang",
            "asn": "AS131279",
        },
    ]

    for idx, payload in enumerate(site_payloads, start=1):
        send_site_event(f"Site Telemetry #{idx}", payload)


def fetch_dashboard() -> None:
    """Login as demo admin and display the dashboard JSON safely."""
    print(f"\n{SEPARATOR}")
    print(" DASHBOARD — All Detected Attacks")
    print(SEPARATOR)

    session = requests.Session()
    try:
        login_resp = session.post(
            AUTH_LOGIN_URL,
            data={"email": "admin@soc.local", "password": "Admin@123"},
            timeout=5,
            allow_redirects=True,
        )

        if login_resp.status_code >= 400:
            print(f"  [ERROR] Login failed with status {login_resp.status_code}")
            return

        resp = session.get(DASH_URL, timeout=5)
        content_type = resp.headers.get("Content-Type", "")

        if "application/json" not in content_type.lower():
            print(f"  [ERROR] Dashboard returned non-JSON content ({content_type or 'unknown content-type'})")
            preview = resp.text[:300].strip()
            if preview:
                print(f"  Preview:\n{preview}")
            return

        data = resp.json()
        print(f"  Total events : {data.get('total_events', 0)}")
        print(f"  Blocked IPs  : {data.get('blocked_ips', [])}")
        print("\n  Attack Log:")
        for entry in data.get("attack_log", []):
            print(f"    • {entry}")

    except requests.exceptions.ConnectionError:
        print("  [ERROR] Cannot connect. Is app.py running?")
    except requests.exceptions.JSONDecodeError:
        print("  [ERROR] Dashboard response was not valid JSON.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + SEPARATOR)
    print("  AI Cyber Attack Detection — Simulation Script")
    print(SEPARATOR)

    time.sleep(0.5)                       # brief pause to ensure server is ready

    simulate_normal_login()               # Scenario 1
    simulate_failed_logins(count=3)       # Scenario 2
    simulate_bruteforce(count=8)          # Scenario 3 — triggers brute-force block
    simulate_ml_detection()               # Scenario 4 — ML predictions
    simulate_site_telemetry()             # Scenario 5 — tenant-scoped events visible in website
    fetch_dashboard()                     # Show full attack log

    print(f"\n{SEPARATOR}")
    print(" Simulation complete.")
    print(SEPARATOR + "\n")
