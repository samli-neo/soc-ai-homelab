# SOC L3 Playbook

## Mission

Perform advanced investigation, approve or execute containment, tune detections, and drive post-incident hardening.

## Response Steps

1. Validate L2 evidence and containment recommendation.
2. Approve only the minimum necessary response action.
3. Preserve evidence before disruptive action when feasible.
4. Use Velociraptor for targeted collection or isolation only after approval.
5. Use pfSense changes only with a clear source/destination/port scope and rollback plan.
6. Use CAPEv2 for malware behavior validation when samples are available and safe to detonate.
7. Update TheHive case with final classification, timeline, scope, and response actions.
8. Convert new findings into Wazuh tuning: decoders, rules, MISP indicators, allowlists, or false-positive suppression.

## Post-Incident Outputs

- Root cause.
- Final MITRE technique list.
- Affected assets and data exposure assessment.
- Actions taken and approvals.
- Detection gaps and tuning changes.
- Executive summary.
- Lessons learned and hardening backlog.
