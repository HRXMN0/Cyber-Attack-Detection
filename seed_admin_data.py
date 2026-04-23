"""
seed_admin_data.py
Inserts rich simulated attack data into cyber_attacks.db for the admin dashboard.
Run once: python seed_admin_data.py
"""
import sqlite3, random, datetime, os

DB_PATH = os.path.join(os.path.dirname(__file__), "cyber_attacks.db")

ATTACKS = [
    # (attack_type, severity, country, city, asn, path, method, ua, site_id)
    ("neptune",    "critical", "RU", "Moscow",       "AS8359",   "/api/auth",          "POST", "python-requests/2.32.3",                          "gov-portal"),
    ("smurf",      "critical", "CN", "Beijing",      "AS4134",   "/admin/login",       "POST", "sqlmap/1.8.9 (https://sqlmap.org)",               "gov-portal"),
    ("back",       "high",     "IR", "Tehran",       "AS44050",  "/wp-admin/",         "GET",  "Nmap/7.95 (nmap.org)",                            "gov-portal"),
    ("teardrop",   "high",     "KP", "Pyongyang",    "AS131279", "/.env",              "GET",  "curl/8.8.0",                                      "gov-portal"),
    ("pod",        "high",     "NG", "Lagos",        "AS37282",  "/.git/config",       "GET",  "Go-http-client/2.0",                              "local"),
    ("satan",      "medium",   "UA", "Kharkiv",      "AS15895",  "/admin/users",       "GET",  "masscan/1.3.2",                                   "local"),
    ("ipsweep",    "medium",   "BR", "São Paulo",    "AS28573",  "/phpmyadmin/",       "GET",  "Nikto/2.1.6",                                     "gov-portal"),
    ("portsweep",  "medium",   "US", "Ashburn",      "AS20473",  "/api/v1/users",      "GET",  "dirbuster/1.0-RC1",                               "local"),
    ("nmap",       "medium",   "DE", "Frankfurt",    "AS58212",  "/actuator/health",   "GET",  "python-requests/2.31.0",                          "gov-portal"),
    ("land",       "high",     "IN", "Mumbai",       "AS17488",  "/xmlrpc.php",        "POST", "WordPress/6.4; attack probe",                     "local"),
    ("neptune",    "critical", "RU", "St. Petersburg","AS12389", "/auth/login",        "POST", "Hydra v9.5 (www.thc.org)",                        "gov-portal"),
    ("smurf",      "critical", "CN", "Shanghai",     "AS4812",   "/api/admin/users",   "DELETE","curl/7.88.1",                                    "gov-portal"),
    ("warezclient","low",      "PK", "Karachi",      "AS45595",  "/download.php",      "GET",  "wget/1.21.4 (linux-gnu)",                         "local"),
    ("warezmaster", "low",     "BD", "Dhaka",        "AS24589",  "/upload.php",        "POST", "python-requests/2.28.0",                          "local"),
    ("rootkit",    "critical", "KP", "Pyongyang",    "AS131279", "/etc/passwd",        "GET",  "nmap 7.95 (https://nmap.org)",                    "gov-portal"),
    ("back",       "high",     "VN", "Ho Chi Minh",  "AS7552",   "/wp-login.php",      "POST", "WPScan v3.8.24",                                  "local"),
    ("neptune",    "critical", "FR", "Paris",        "AS3215",   "/api/token",         "POST", "libcurl/7.68.0",                                  "gov-portal"),
    ("ipsweep",    "medium",   "NL", "Amsterdam",    "AS1103",   "/manager/html",      "GET",  "ZGrab/2.x (zgrab2)",                              "local"),
    ("teardrop",   "high",     "AU", "Sydney",       "AS1221",   "/config/database",   "GET",  "python-requests/2.30.0",                          "gov-portal"),
    ("pod",        "high",     "CA", "Toronto",      "AS577",    "/api/keys",          "GET",  "Go-http-client/1.1",                              "local"),
    ("satan",      "medium",   "MX", "Mexico City",  "AS22927",  "/cgi-bin/test.cgi",  "GET",  "Httprint v301",                                   "gov-portal"),
    ("normal",     "None",     "US", "New York",     "AS396982", "/index.html",        "GET",  "Mozilla/5.0 Chrome/124",                          "gov-portal"),
    ("normal",     "None",     "IN", "Delhi",        "AS9829",   "/about",             "GET",  "Mozilla/5.0 Safari/17",                           "gov-portal"),
    ("nmap",       "medium",   "SG", "Singapore",    "AS55256",  "/api/v2/admin",      "GET",  "masscan/1.0 (https://github.com)",               "gov-portal"),
    ("rootkit",    "critical", "IR", "Isfahan",      "AS44050",  "/shell.php",         "POST", "python-requests/2.27.1",                          "gov-portal"),
    ("smurf",      "critical", "RU", "Kazan",        "AS12389",  "/admin",             "POST", "sqlmap/1.7.11 (SQLite, Python 3.11, Linux)",      "gov-portal"),
    ("back",       "high",     "PL", "Warsaw",       "AS5617",   "/.htaccess",         "GET",  "nikto/2.1.6",                                     "local"),
    ("ipsweep",    "medium",   "RO", "Bucharest",    "AS8264",   "/backup.zip",        "GET",  "wget/1.20.3",                                     "local"),
    ("pod",        "high",     "HK", "Hong Kong",    "AS9304",   "/private/dump.sql",  "GET",  "curl/7.80.0",                                     "gov-portal"),
    ("warezclient","low",      "TH", "Bangkok",      "AS7470",   "/wp-content/uploads","GET",  "python-requests/2.26.0",                          "local"),
]

def random_past_ts(hours_ago_min=1, hours_ago_max=72):
    delta = datetime.timedelta(seconds=random.randint(hours_ago_min*3600, hours_ago_max*3600))
    return (datetime.datetime.utcnow() - delta).isoformat() + "Z"

def ip_for(country):
    # Generate plausible-looking IP per country range
    RANGES = {
        "RU": ("185.220.101", "91.108."), "CN": ("60.191.", "1.180."), "IR": ("77.104.", "91.98."),
        "KP": ("175.45.179", "45.33."), "NG": ("41.57.", "41.203."), "UA": ("194.165.", "31.128."),
        "BR": ("189.112.", "187.34."), "US": ("104.244.", "198.51.100."), "DE": ("45.153.", "85.214."),
        "IN": ("103.21.", "117.247."), "PK": ("182.180.", "103.31."), "FR": ("77.158.", "91.144."),
        "NL": ("45.138.", "185.220."), "AU": ("203.25.", "49.179."), "CA": ("142.250.", "104.153."),
        "MX": ("200.57.", "189.220."), "SG": ("103.6.", "124.6."), "PL": ("83.1.", "5.182."),
        "RO": ("5.2.", "79.112."), "HK": ("43.252.", "202.14."), "VN": ("171.27.", "14.237."),
        "BD": ("103.111.", "103.4."), "TH": ("171.97.", "203.147."), "PH": ("49.145.", "112.198."),
    }
    prefix = random.choice(RANGES.get(country, ["198.51.",])) if country in RANGES else "198.51.100."
    return prefix + str(random.randint(1, 254))

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

inserted = 0
for attack_type, severity, country, city, asn, path, method, ua, site_id in ATTACKS:
    # Insert 2-5 events per scenario with varying times
    repeat = random.randint(2, 5) if severity == "critical" else random.randint(1, 3)
    for _ in range(repeat):
        ip  = ip_for(country)
        ts  = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=random.randint(3600, 72*3600))).isoformat().replace("+00:00","Z")
        c.execute("""
            INSERT INTO attack_log
              (ip, attack, severity, timestamp, site_id, user_agent, method, path, referer, country, city, asn, bytes_in)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            ip, attack_type, severity, ts,
            site_id, ua, method, path,
            "http://evil-ref.example.com" if severity in ("critical","high") else "",
            country, city, asn,
            random.randint(64, 65536),
        ))
        inserted += 1


conn.commit()
conn.close()
print(f"[SEED] OK - Inserted {inserted} realistic attack events into {DB_PATH}")

