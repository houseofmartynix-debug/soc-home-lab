"""
log_parser.py — quick offline triage of a Wazuh alerts.json export.

Reads /var/ossec/logs/alerts/alerts.json (or any file passed as argv[1]) and
prints summary stats that mirror what a Tier 1 analyst checks first thing
in the morning:

  - Top 10 rule IDs by alert count
  - Top 10 source IPs across all alerts
  - Top 10 affected agents
  - Highest-severity alerts (level >= 10) in chronological order

Usage:
    python3 log_parser.py /var/ossec/logs/alerts/alerts.json
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def load_alerts(path: Path) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def top(counter: Counter, n: int = 10) -> str:
    return "\n".join(f"  {count:>6}  {key}" for key, count in counter.most_common(n))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: log_parser.py <alerts.json>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 1

    alerts = load_alerts(path)
    if not alerts:
        print("no alerts parsed.")
        return 0

    rules = Counter(a.get("rule", {}).get("id", "?") for a in alerts)
    src_ips = Counter(a.get("data", {}).get("srcip") for a in alerts if a.get("data", {}).get("srcip"))
    agents = Counter(a.get("agent", {}).get("name", "?") for a in alerts)

    high_sev = sorted(
        (a for a in alerts if int(a.get("rule", {}).get("level", 0)) >= 10),
        key=lambda a: a.get("timestamp", ""),
    )

    print(f"Loaded {len(alerts)} alerts from {path}\n")
    print("Top rule IDs:")
    print(top(rules))
    print("\nTop source IPs:")
    print(top(src_ips))
    print("\nTop agents:")
    print(top(agents))

    print(f"\nHigh-severity (level >= 10): {len(high_sev)}")
    for a in high_sev[:20]:
        ts = a.get("timestamp", "?")
        rid = a.get("rule", {}).get("id", "?")
        desc = a.get("rule", {}).get("description", "?")
        host = a.get("agent", {}).get("name", "?")
        print(f"  {ts}  rule={rid}  host={host}  {desc}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
