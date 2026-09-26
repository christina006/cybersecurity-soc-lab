Investigation Playbook — PowerShell to Command Prompt Chain

## Objective

Review an execution chain where PowerShell spawns `cmd.exe`, using parent-child context instead of treating either process independently.

## Safe simulation

Use this harmless command on the isolated endpoint:

```powershell
powershell.exe -NoProfile -Command "Start-Process cmd.exe '/c echo SOC-LAB-TEST' -Wait"
```

The child process only prints a label and exits.

## Triage steps

1. Locate Sysmon Event ID 1 for `cmd.exe` and verify that `ParentImage` is PowerShell.
2. Correlate `ParentProcessGuid` to the earlier PowerShell process creation event.
3. Compare both command lines, users, integrity levels, and hashes.
4. Search for child processes, file writes, network connections, or registry events connected to either Process GUID.
5. Assign a verdict: expected automation, benign lab test, suspicious, or confirmed malicious behavior.

## Evidence standard

Include a process tree and all relevant Process GUIDs in the report. A textual process tree is acceptable when the dashboard cannot export a graph.