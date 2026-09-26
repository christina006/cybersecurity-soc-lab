Detection Rules

These are **portable Sigma rules**, not drop-in Wazuh XML. Sigma provides a clear, SIEM-independent statement of the detection intent; each rule needs field mapping and testing before production use.

| Rule | Type | Test evidence | Tuning focus |
| --- | --- | --- | --- |
| `windows-failed-logon.yml` | Base event | Security Event ID 4625 | Service accounts, expected password resets |
| `brute-force.yml` | Correlation | Five matching failed-logon events in five minutes | Threshold and grouping fields |
| `powershell-execution.yml` | Process creation | Sysmon Event ID 1 | Approved automation and management tools |
| `powershell-cmd-child.yml` | Parent-child relationship | Sysmon Event ID 1 | Administrative scripts that intentionally call `cmd.exe` |

## Rule lifecycle

1. Validate field names against actual Wazuh-indexed events.
2. Test the rule against the safe fixture and a real lab event.
3. Record expected and unexpected hits.
4. Add narrow, documented exclusions only when evidence supports them.
5. Promote from `experimental` after repeated validation.

The correlation file follows the [Sigma Correlation Rule specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md). It references the failed-logon base rule by UUID.