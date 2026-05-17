"""
alert_enrichment.py — quick enrichment helper for Wazuh alerts.

Reads a single Wazuh alert (JSON, one line from /var/ossec/logs/alerts/alerts.json)
from stdin and enriches it with:
  - GeoIP for source IP (via free ip-api.com — no key required)
  - AbuseIPDB reputation (if ABUSEIPDB_KEY env var set)
  - VirusTotal hash lookup for file hashes in the alert (if VT_API_KEY env var set)

Usage:
    tail -F /var/ossec/logs/alerts/alerts.json | python3 alert_enrichment.py

Demo:
    echo '{"rule":{"id":"100100"},"data":{"srcip":"8.8.8.8"}}' | python3 alert_enrichment.py

This is a learning tool, not a production script. In a real SOC the same enrichment
would be performed by a SOAR (Shuffle, Tines, n8n) or by the SIEM's own integrations.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import urllib.request
import urllib.error

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

TIMEOUT = 5


def _http_get_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def geoip(ip: str) -> dict[str, Any] | None:
    data = _http_get_json(f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as,query")
    if data and data.get("query"):
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
        }
    return None


def abuseipdb(ip: str) -> dict[str, Any] | None:
    if not ABUSEIPDB_KEY:
        return None
    data = _http_get_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
    )
    if data and "data" in data:
        return {
            "abuse_confidence_score": data["data"].get("abuseConfidenceScore"),
            "total_reports": data["data"].get("totalReports"),
        }
    return None


def virustotal(sha256: str) -> dict[str, Any] | None:
    if not VT_API_KEY:
        return None
    data = _http_get_json(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_API_KEY},
    )
    if data and "data" in data:
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return {"malicious_vendor_count": stats.get("malicious", 0), "total_vendors": sum(stats.values())}
    return None


def enrich(alert: dict[str, Any]) -> dict[str, Any]:
    enriched: dict[str, Any] = {}
    srcip = alert.get("data", {}).get("srcip")
    if srcip:
        enriched["srcip"] = srcip
        enriched["geoip"] = geoip(srcip)
        enriched["abuseipdb"] = abuseipdb(srcip)

    # Try common hash fields used by Sysmon-derived alerts
    hashes = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("hashes", "")
    sha256 = next((h.split("=", 1)[1] for h in hashes.split(",") if h.startswith("SHA256=")), None)
    if sha256:
        enriched["sha256"] = sha256
        enriched["virustotal"] = virustotal(sha256)

    return enriched


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            print(f"# skipped non-JSON line: {line[:80]}", file=sys.stderr)
            continue
        result = {"rule_id": alert.get("rule", {}).get("id"), "enrichment": enrich(alert)}
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
