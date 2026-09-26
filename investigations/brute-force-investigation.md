Investigation Playbook — Repeated Failed Logons

## Objective

Determine whether repeated Windows Security Event ID 4625 records indicate a likely password attack, a user mistake, or a faulty service configuration.

## Safe simulation

Do not automate password attempts against a real account. Use the synthetic fixture for offline validation. In the live lab, generate only a small, manually controlled set of failed attempts against the dedicated `labuser` account, then stop and document the result.

## Detection hypothesis

Five failures for the same `Computer`, `TargetUserName`, and `IpAddress` in five minutes indicate a possible brute-force attempt. A later Event ID 4624 from the same source increases priority but does not by itself prove compromise.

## Triage steps

1. Confirm Event ID 4625 and normalize the target user, source address, host, logon type, status, and substatus.
2. Build a five-minute timeline around the first failure. Include nearby Event ID 4624 records.
3. Determine whether the source is an approved management host, VPN gateway, or expected user location.
4. Check whether failures affect one account or many accounts; broad targeting changes the hypothesis.
5. Review the successful logon, if any, for its logon type and subsequent process activity.
6. State the confidence level and list the evidence that would confirm or refute the finding.

## Evidence to retain

| Field | Why it matters |
| --- | --- |
| UTC timestamp | Reconstructs order and duration |
| Computer | Identifies the destination endpoint |
| TargetUserName | Identifies the targeted account |
| IpAddress | Identifies the source in the lab |
| LogonType / status | Explains the authentication context |
| Event IDs 4625 and 4624 | Preserves failed and successful authentication evidence |

## Escalation guidance

For a real environment, contain a confirmed compromise by following the organization’s incident procedure: protect the account, preserve evidence, and investigate the source. This lab does not perform containment automatically.