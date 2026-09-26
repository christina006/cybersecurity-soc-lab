Incident #001 — Repeated Failed Authentication Attempts

| Field | Value |
| --- | --- |
| Case status | Closed — benign synthetic exercise |
| Severity | Medium (detection severity); informational after validation |
| Detection | Possible Windows Brute Force Against a User Account |
| ATT&CK | T1110 — Brute Force |
| Affected host | `WIN11-LAB-01` |
| Target account | `labuser` |
| Source | `192.0.2.44` (RFC 5737 documentation address) |
| Analysis window | 2026-09-17 14:32:01–14:32:41 UTC |

## Executive summary

The correlation rule detected five failed network logons against the `labuser` test account from a single synthetic source within 28 seconds. A successful network logon followed 12 seconds later. Review of the fixture and lab exercise plan confirms that every record was deliberately generated for detection validation; no real account, source, or unauthorized activity was involved.

## Timeline

| Time (UTC) | Event ID | Observation |
| --- | --- | --- |
| 14:32:01 | 4625 | First failed network logon for `labuser` from `192.0.2.44` |
| 14:32:08 | 4625 | Second failed logon |
| 14:32:15 | 4625 | Third failed logon |
| 14:32:22 | 4625 | Fourth failed logon |
| 14:32:29 | 4625 | Fifth failed logon; correlation threshold reached |
| 14:32:41 | 4624 | Successful network logon from the same synthetic source |

## Investigation and verdict

The five Event ID 4625 records share destination host, account, and source values and therefore correctly satisfy the five-events-in-five-minutes rule. The source address is reserved for documentation, and the event messages explicitly identify themselves as safe synthetic events. No endpoint process, network, or account-change evidence indicates post-authentication activity.

**Verdict:** Benign lab simulation. The detection performed as designed.

## Potential impact in a real environment

The same pattern could precede an account takeover if a successful authentication were unauthorized. Potential effects include unauthorized access under the targeted account and follow-on execution using that identity.

## Recommendations

1. Baseline known service accounts and approved management sources before enabling automatic escalation.
2. Raise priority when a successful logon follows repeated failures from the same source.
3. Alert separately on password spraying across multiple accounts and on unusual successful logon types.
4. Retain Security Event IDs 4624 and 4625 with enough context for timely correlation.

## Evidence references

- `data/samples/soc-lab-events.jsonl`, rows 1–6
- `detection-rules/windows-failed-logon.yml`
- `detection-rules/brute-force.yml`