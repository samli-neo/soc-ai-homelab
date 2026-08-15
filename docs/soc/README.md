# SOC Wazuh Customization Package

This package turns Wazuh into the SOC control plane for the lab.

## Capability Map

| Capability | Implementation |
| --- | --- |
| Centralized log collection | Wazuh agents `001` pfSense, `002` homelab, `004` Windows endpoint, plus pfSense syslog UDP/514. |
| Normalization | Custom decoders in `configs/wazuh-manager/soc_decoders.xml` normalize pfSense filterlog and pfSense Snort CSV fields. |
| Malicious behavior detection | Local Wazuh rules in `configs/wazuh-manager/local_rules.xml` cover IDS priority, firewall brute-force patterns, privileged logons, and repeated suspicious activity. |
| Multi-source correlation | Wazuh correlation rules escalate repeated firewall blocks, repeated IDS events, repeated non-business logins, and repeated privileged Windows logons. |
| MITRE ATT&CK mapping | Custom rules include MITRE IDs such as `T1046`, `T1078`, `T1110`, `T1190`, `T1204`, `T1071`, and `T1105`. |
| False-positive reduction | pfSense base block events are low-level/no-log for routing, Snort priority 3 remains low, and optional upstream noisy rules are excluded. |
| Risk prioritization | Groups `soc_risk_medium`, `soc_risk_high`, `soc_risk_critical`, and `incident_candidate` are used for routing and dashboards. |
| Threat intelligence | `configs/wazuh-manager/misp_ioc_rules.xml` maps MISP IP/domain/hash matches to high/critical SOC risks. |
| Incident response automation | Wazuh sends level `7+` alerts to `soc-intake-router`; level `<9` is digest-only, level `>=9` runs Shuffle with approval-gated IR actions. |
| Workflow health metrics | `soc-intake-router` exposes `GET /metrics` for in-memory route counters, reason/rule counts, errors, and last routing decision. |
| Case management | Shuffle calls the internal TheHive dedup gate before creating/updating cases. |
| Analyzer support | Cortex and CAPEv2 paths are modeled as enrichment/analysis gates; containment remains approval-gated. |
| n8n extension | n8n should subscribe behind Shuffle or a dedicated webhook for ticketing, chatops, and non-security business notifications. |
| SOC playbooks | L1/L2/L3 analyst flows are under `docs/soc/playbooks/`. |
| Reports | Operational and executive report templates are under `docs/soc/reports/`. |
| Dashboards | Wazuh/OpenSearch dashboard specification is under `dashboards/wazuh-soc-dashboard-spec.json`. |

## Alert Severity Policy

| Wazuh Level | SOC Meaning | Default Action |
| --- | --- | --- |
| 0-2 | Noise / archive / correlation input | Store only. |
| 3-6 | Low signal alert | Dashboard and optional digest. |
| 7-8 | Medium risk | Digest, analyst review, enrichment allowed. |
| 9-11 | High risk | Shuffle workflow, TheHive case, advisor output, approval-gated response. |
| 12-15 | Critical risk | Shuffle workflow, TheHive case, priority analyst escalation, approval-gated containment. |

## Validation Commands

Run health plus Wazuh regression:

```powershell
powershell -ExecutionPolicy Bypass -File "scripts\test-soc.ps1"
```

Deploy Wazuh config after local edits:

```powershell
powershell -ExecutionPolicy Bypass -File "scripts\deploy-wazuh-config.ps1" -RunRegression
```
