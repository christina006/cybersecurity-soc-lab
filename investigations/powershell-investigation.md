Investigation Playbook — PowerShell Execution

## Objective

Assess whether a PowerShell process is expected administrative activity or requires investigation.

## Safe simulation

On the isolated endpoint, run the following harmless command as the test user:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-TEST'"
```

It only writes a text marker to the console. It does not download, execute, modify, or persist anything.

## Triage steps

1. Confirm Sysmon Event ID 1 and capture the complete `Image`, `CommandLine`, `ParentImage`, `User`, hashes, and Process GUID.
2. Determine whether the parent process and user are expected for the endpoint.
3. Review command-line intent. Treat encoded, remote, or execution-chain indicators as a reason for deeper investigation; do not infer maliciousness merely because PowerShell ran.
4. Pivot by Process GUID for related child processes and nearby Sysmon events.
5. Compare with approved maintenance activity and document the decision.

## Detection decision

The rule is intentionally broad for a student lab, so the correct analyst conclusion for the supplied test is **benign test activity**, not an incident. The value is in showing the alert-to-verdict workflow and appropriate tuning.