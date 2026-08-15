# SOC L2 Playbook

## Mission

Determine scope, validate impact, enrich observables, and decide whether containment approval is required.

## Investigation Steps

1. Review L1 notes, Wazuh alert JSON, TheHive case, and dedup history.
2. Build a timeline across Wazuh agents, pfSense syslog, Snort IDS, Windows EventChannel, and Linux journald.
3. Enrich IPs, domains, URLs, and hashes with MISP, Cortex analyzers, and CAPEv2 where applicable.
4. Identify MITRE tactics and techniques represented by the alert chain.
5. Determine blast radius: hosts, accounts, network segments, repeated sources, and persistence indicators.
6. Check whether the event is isolated, repeated, or part of a broader campaign.
7. Request approval for Velociraptor collection, endpoint isolation, pfSense blocking, or malware detonation only when evidence justifies it.

## Containment Decision Criteria

- Confirmed malware hash or CAPEv2 malicious verdict.
- Active exploitation attempt with repeated IDS/firewall correlation.
- Privileged account misuse.
- Lateral movement indicators.
- Evidence of command-and-control or data exfiltration.

## L2 Outputs

- Incident hypothesis.
- Evidence-backed scope.
- MITRE mapping.
- Enrichment summary.
- Containment recommendation with risk and rollback notes.
- Escalation to L3 if root cause, malware behavior, or infrastructure changes require deeper expertise.
