#!/usr/bin/env python3
"""Offline, dependency-free validation for the safe SOC lab event fixture.

This utility mirrors the intent of the repository's Sigma detections; it is not
a replacement for Wazuh or a Sigma backend. It exists so reviewers can inspect
expected alerts without needing an SIEM.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


WINDOW = timedelta(minutes=5)


def load_events(path: Path) -> list[dict[str, Any]]:
    """Read newline-delimited JSON and reject malformed or time-less evidence."""
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            event["_time"] = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except (json.JSONDecodeError, KeyError, ValueError) as error:
            raise ValueError(f"Invalid event at line {line_number}: {error}") from error
        events.append(event)
    return sorted(events, key=lambda item: item["_time"])


def detect_brute_force(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Alert once per matching user/source/host group in the five-minute window."""
    failures: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("event_id") == 4625:
            key = (event.get("computer", "unknown"), event.get("target_user_name", "unknown"), event.get("ip_address", "unknown"))
            failures[key].append(event)

    alerts: list[dict[str, Any]] = []
    for (computer, user, source), group in failures.items():
        start = 0
        for end, event in enumerate(group):
            while event["_time"] - group[start]["_time"] > WINDOW:
                start += 1
            count = end - start + 1
            if count == 5:
                alerts.append({
                    "rule": "Possible Windows Brute Force Against a User Account",
                    "severity": "medium",
                    "mitre": "T1110",
                    "computer": computer,
                    "user": user,
                    "source": source,
                    "first_seen": group[start]["timestamp"],
                    "last_seen": event["timestamp"],
                    "evidence_count": count,
                })
    return alerts


def ends_with(value: str, names: tuple[str, ...]) -> bool:
    return value.lower().endswith(names)


def detect_process_activity(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    powershell_names = ("\\powershell.exe", "\\pwsh.exe")
    for event in events:
        if event.get("event_id") != 1:
            continue
        image = event.get("process_image", "")
        parent = event.get("parent_image", "")
        common = {
            "computer": event.get("computer", "unknown"),
            "user": event.get("user", "unknown"),
            "timestamp": event.get("timestamp"),
            "image": image,
            "command_line": event.get("command_line", ""),
        }
        if ends_with(image, powershell_names):
            alerts.append({"rule": "PowerShell Process Creation", "severity": "medium", "mitre": "T1059.001", **common})
        if ends_with(image, ("\\cmd.exe",)) and ends_with(parent, powershell_names):
            alerts.append({"rule": "Command Shell Spawned by PowerShell", "severity": "medium", "mitre": "T1059.003", "parent_image": parent, **common})
    return alerts


def print_alert(alert: dict[str, Any]) -> None:
    print(f"[{alert['severity'].upper()}] {alert['rule']} ({alert['mitre']})")
    for key, value in alert.items():
        if key not in {"rule", "severity", "mitre"}:
            print(f"  {key}: {value}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyse safe Mini SOC lab JSONL events.")
    parser.add_argument("--input", type=Path, required=True, help="Path to newline-delimited JSON events")
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error(f"Input file does not exist: {args.input}")

    try:
        events = load_events(args.input)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    alerts = detect_brute_force(events) + detect_process_activity(events)
    if not alerts:
        print("No detections matched.")
        return 1
    for alert in alerts:
        print_alert(alert)
    print(f"\n{len(alerts)} alert(s) matched across {len(events)} event(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
