#!/usr/bin/env python3
"""Generate the repository's harmless, deterministic test-event fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def event(timestamp: str, event_id: int, **fields: object) -> dict[str, object]:
    return {"timestamp": timestamp, "event_id": event_id, "computer": "WIN11-LAB-01", **fields}


def build_fixture() -> list[dict[str, object]]:
    failed = [
        event(
            f"2026-09-17T14:32:{second:02d}Z",
            4625,
            channel="Security",
            target_user_name="labuser",
            ip_address="192.0.2.44",
            logon_type=3,
            status="0xC000006D",
            message="Failed network logon (safe synthetic event).",
        )
        for second in (1, 8, 15, 22, 29)
    ]
    return failed + [
        event(
            "2026-09-17T14:32:41Z",
            4624,
            channel="Security",
            target_user_name="labuser",
            ip_address="192.0.2.44",
            logon_type=3,
            message="Successful network logon (safe synthetic event).",
        ),
        event(
            "2026-09-17T14:34:00Z",
            1,
            channel="Microsoft-Windows-Sysmon/Operational",
            user="LAB\\labuser",
            process_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_image="C:\\Windows\\explorer.exe",
            command_line="powershell.exe -NoProfile -Command Write-Output 'SOC-LAB-TEST'",
            parent_command_line="C:\\Windows\\explorer.exe",
            process_guid="{LAB-0001}",
            message="Benign PowerShell process creation.",
        ),
        event(
            "2026-09-17T14:34:03Z",
            1,
            channel="Microsoft-Windows-Sysmon/Operational",
            user="LAB\\labuser",
            process_image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="cmd.exe /c echo SOC-LAB-TEST",
            parent_command_line="powershell.exe -NoProfile -Command Start-Process cmd.exe '/c echo SOC-LAB-TEST'",
            process_guid="{LAB-0002}",
            parent_process_guid="{LAB-0001}",
            message="Benign PowerShell to Command Prompt process chain.",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Write safe synthetic Mini SOC lab events as JSONL.")
    parser.add_argument("--output", type=Path, required=True, help="Output JSONL file")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    records = "\n".join(json.dumps(item, separators=(",", ":")) for item in build_fixture()) + "\n"
    args.output.write_text(records, encoding="utf-8")
    print(f"Wrote {len(build_fixture())} safe synthetic event(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
