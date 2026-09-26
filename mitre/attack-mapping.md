MITRE ATT&CK Mapping

This table records what the lab can observe and why the corresponding technique is relevant. A technique tag describes observed behavior; it does not establish attacker intent by itself.

| Detection | Technique | Tactic | Evidence required | Analyst question |
| --- | --- | --- | --- | --- |
| Repeated failed Windows logons | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access | Security Event ID 4625; account, source, and time window | Is this a repeated user error, misconfiguration, or an attempt to guess credentials? |
| PowerShell process creation | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Execution | Sysmon Event ID 1; image, command line, parent, user, and Process GUID | Is the command expected, and does its context match approved activity? |
| `cmd.exe` spawned by PowerShell | [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | Execution | Two linked Sysmon Event ID 1 records; parent and child command lines | Is the chain expected automation or an unusual execution path? |

## Mapping methodology

1. Start from an observable event, not from an assumed technique.
2. Map the behavior to the most precise ATT&CK technique supported by its evidence.
3. Preserve the supporting event fields in the investigation.
4. Note ambiguity. For example, ordinary administrator use of PowerShell is execution activity but not necessarily adversary activity.
5. Use the mapping to guide further telemetry collection and response—not as an automatic verdict.

## Current coverage limits

This lab does not claim coverage for persistence, defense evasion, credential dumping, lateral movement, or exfiltration. Those areas need their own approved scenarios, telemetry requirements, detections, and safety review.