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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL   = "http://127.0.0.1:5000"
LOGIN_URL  = f"{BASE_URL}/login"
DASH_URL   = f"{BASE_URL}/dashboard"

SEPARATOR  = "=" * 70


def pretty(data: dict) -> str:
    """Return a nicely formatted JSON string."""
    return json.dumps(data, indent=2)


def send_request(label: str, payload: dict, delay: float = 2.0) -> None:
    """Send a single POST to /login and print the result."""
    print(f"\n[{label}]")
    print(f"  Payload : {payload}")
    try:
        resp = requests.post(LOGIN_URL, json=payload, timeout=5)
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
        label   = "Normal Login",
        payload = {"username": "alice", "password": "Str0ng@Pass!"},
    )


def simulate_failed_logins(count: int = 3) -> None:
    """Simulate a few failed logins (below brute-force threshold)."""
    print(f"\n{SEPARATOR}")
    print(f" SCENARIO 2 — {count} Failed Login Attempts (below threshold)")
    print(SEPARATOR)
    for i in range(1, count + 1):
        send_request(
            label   = f"Failed Login #{i}",
            payload = {"username": "bob", "password": ""},   # empty pw → failure
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
            label   = f"Brute Force #{i}",
            payload = {"username": "admin", "password": ""},
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
        send_request(label="ML Prediction", payload=p)


def fetch_dashboard() -> None:
    """Fetch and display the admin dashboard."""
    print(f"\n{SEPARATOR}")
    print(" DASHBOARD — All Detected Attacks")
    print(SEPARATOR)
    try:
        resp = requests.get(DASH_URL, timeout=5)
        data = resp.json()
        print(f"  Total events : {data.get('total_events', 0)}")
        print(f"  Blocked IPs  : {data.get('blocked_ips', [])}")
        print("\n  Attack Log:")
        for entry in data.get("attack_log", []):
            print(f"    • {entry}")
    except requests.exceptions.ConnectionError:
        print("  [ERROR] Cannot connect. Is app.py running?")


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
    fetch_dashboard()                     # Show full attack log

    print(f"\n{SEPARATOR}")
    print(" Simulation complete.")
    print(SEPARATOR + "\n")
