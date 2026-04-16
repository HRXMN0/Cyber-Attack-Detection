# =============================================================================
# utils.py — Intelligence Layer
# Provides severity classification and mitigation responses for detected attacks
# =============================================================================

# ---------------------------------------------------------------------------
# Severity Mapping
# ---------------------------------------------------------------------------
SEVERITY_MAP = {
    # Normal traffic
    "normal": "None",

    # DoS attacks
    "neptune": "Critical",
    "back": "High",
    "land": "High",
    "pod": "High",
    "smurf": "Critical",
    "teardrop": "High",
    "apache2": "High",
    "udpstorm": "Critical",
    "processtable": "High",
    "mailbomb": "High",

    # Probe attacks
    "ipsweep": "Medium",
    "nmap": "Medium",
    "portsweep": "Medium",
    "satan": "Medium",
    "mscan": "Medium",
    "saint": "Medium",

    # R2L (Remote to Local) attacks
    "ftp_write": "High",
    "guess_passwd": "High",
    "imap": "High",
    "multihop": "High",
    "phf": "Medium",
    "spy": "High",
    "warezclient": "Medium",
    "warezmaster": "High",
    "sendmail": "High",
    "named": "High",
    "snmpgetattack": "High",
    "snmpguess": "High",
    "xlock": "Medium",
    "xsnoop": "Medium",
    "worm": "Critical",

    # U2R (User to Root) privilege escalation
    "buffer_overflow": "Critical",
    "loadmodule": "Critical",
    "perl": "High",
    "rootkit": "Critical",
    "httptunnel": "High",
    "ps": "High",
    "sqlattack": "Critical",
    "xterm": "High",

    # Brute force (custom)
    "bruteforce": "Critical",

    # Unknown fallback
    "unknown": "Medium",
}

# ---------------------------------------------------------------------------
# Response / Mitigation Mapping
# ---------------------------------------------------------------------------
RESPONSE_MAP = {
    "None": "No action required — traffic is normal.",
    "Critical": (
        "IMMEDIATE ACTION: Permanently block IP, isolate affected systems, "
        "trigger incident response, alert SOC team, and preserve forensic evidence."
    ),
    "High": (
        "URGENT: Temporarily block IP for 24 hours, increase logging verbosity, "
        "notify security team, and review firewall rules."
    ),
    "Medium": (
        "WARNING: Monitor IP closely, apply rate limiting, "
        "flag for manual review by security analyst."
    ),
    "Low": "NOTICE: Log the event and continue passive monitoring.",
}


def get_severity(attack_type: str) -> str:
    """
    Return the severity level for a given attack type.

    Parameters
    ----------
    attack_type : str
        The predicted attack label (e.g. 'neptune', 'normal', 'bruteforce').

    Returns
    -------
    str
        One of 'None', 'Low', 'Medium', 'High', 'Critical'.
    """
    normalized = str(attack_type).lower().strip().rstrip(".")
    return SEVERITY_MAP.get(normalized, "Medium")


def get_response(severity: str) -> str:
    """
    Return the recommended mitigation action for a given severity level.

    Parameters
    ----------
    severity : str
        One of 'None', 'Low', 'Medium', 'High', 'Critical'.

    Returns
    -------
    str
        A human-readable mitigation action string.
    """
    return RESPONSE_MAP.get(severity, RESPONSE_MAP["Medium"])