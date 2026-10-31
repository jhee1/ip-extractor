"""IP Extractor

Analyzes an SSH auth log, finds IP addresses with repeated failed logins
and enriches them with threat intelligence from AbuseIPDB.

Usage:
    python IP_extract.py <log_file> <threshold>
"""

import ipaddress
import os
import re
import sys
from collections import Counter

import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.environ.get("ABUSEIPDB_KEY")

# Log lines that describe a failed login attempt
FAILED_LOGIN_MARKERS = (
    "Failed password",
    "Failed publickey",
    "authentication failure",
)

IPV4_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"


def is_valid_ip(ip):
    """Return True if every octet is in the 0-255 range."""
    for octet in ip.split("."):
        if int(octet) > 255:
            return False
    return True


def check_ip(ip):
    """Look up an IP in AbuseIPDB. Returns a dict, or None if the lookup failed."""
    if not API_KEY:
        return None

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )

    if response.status_code != 200:
        return None

    data = response.json()["data"]
    return {
        "score": data["abuseConfidenceScore"],
        "reports": data["totalReports"],
        "users": data["numDistinctUsers"],
        "country": data["countryCode"],
        "isp": data["isp"],
        "usage_type": data["usageType"],
        "tor": data["isTor"],
        "whitelisted": data["isWhitelisted"],
        "last_reported": data["lastReportedAt"],
    }


def analyze_log(path, threshold):
    """Return a list of (ip, failed_attempts) with at least `threshold` failures."""
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()

    addresses = []
    for line in text.splitlines():
        if any(marker in line for marker in FAILED_LOGIN_MARKERS):
            for candidate in re.findall(IPV4_PATTERN, line):
                if is_valid_ip(candidate):
                    addresses.append(candidate)

    counts = Counter(addresses)

    suspicious = []
    for ip, count in counts.most_common():
        if count >= threshold:
            suspicious.append((ip, count))
    return suspicious


def main():
    if len(sys.argv) != 3:
        print("Usage: python IP_extract.py <log_file> <threshold>")
        sys.exit(1)

    path = sys.argv[1]
    threshold = int(sys.argv[2])

    if not API_KEY:
        print("Warning: ABUSEIPDB_KEY not set, threat intelligence lookups are disabled.")

    results = analyze_log(path, threshold)

    if not results:
        print(f"No addresses with at least {threshold} failed attempts.")

    with open("alerts.txt", "w", encoding="utf-8") as f:
        for ip, count in results:
            if ipaddress.ip_address(ip).is_private:
                f.write(f"ALERT: {ip} --> failed attempts: {count} | private address, no TI lookup\n")
                continue

            ti = check_ip(ip)
            if ti is None:
                f.write(f"ALERT: {ip} --> failed attempts: {count} | TI unavailable\n")
                continue

            f.write(
                f"ALERT: {ip} --> failed attempts: {count} | abuse score: {ti['score']} | "
                f"country: {ti['country']} | ISP: {ti['isp']} | Tor: {ti['tor']}\n"
            )


if __name__ == "__main__":
    main()