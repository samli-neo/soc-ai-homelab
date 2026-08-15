# SOC L1 Playbook

## Mission

Validate alert quality, collect context, suppress obvious false positives, and escalate when risk or uncertainty is high.

## Triage Steps

1. Confirm alert freshness and source agent.
2. Check Wazuh rule level, description, MITRE ID, and SOC risk group.
3. Identify affected asset, source IP, destination IP, user, process, and observable.
4. Search for related alerts from the same source, user, host, or rule in the last 24 hours.
5. Check whether TheHive dedup already has an open case.
6. Mark false positives only when there is a clear benign explanation.
7. Escalate to L2 when there is confirmed malicious behavior, repeated suspicious activity, threat-intel match, privileged account activity, or unclear business context.

## Escalation Triggers

- Wazuh level `9+`.
- Any group `soc_risk_high`, `soc_risk_critical`, or `incident_candidate`.
- MISP IOC match.
- Repeated IDS or firewall correlation.
- Privileged login outside expected activity.
- Windows privileged logon correlated with other endpoint alerts.

## L1 Outputs

- Alert classification: true positive, false positive, benign true positive, needs L2.
- Short timeline.
- Affected asset and user.
- Evidence links: Wazuh alert ID, TheHive case, related alerts.
- Recommended next action.
