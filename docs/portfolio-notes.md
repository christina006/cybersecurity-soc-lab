Portfolio Presentation Notes

## CV entry

Designed and deployed a Windows security-monitoring lab using Wazuh and Sysmon. Developed portable detections for repeated failed authentication, PowerShell execution, and suspicious parent-child process activity; mapped findings to MITRE ATT&CK and documented investigations through incident reports.

## project walkthrough

1. Start with the architecture: Windows endpoint, agent, SIEM, detection, investigation.
2. Show one raw Security Event ID 4625 and one correlated alert.
3. Explain why the correlation groups by host, user, and source and why its threshold is experimental.
4. Show the Sysmon process tree and distinguish detection from a final analyst verdict.
5. Open the incident report and discuss evidence, limitations, and tuning recommendations.

## What makes this professional

- Reproducible scope and explicit safety boundary
- Detection logic separated from platform implementation
- Clear ATT&CK mapping with evidence requirements
- Honest treatment of false positives and coverage limits
- Reports that differentiate observed facts from analyst inference