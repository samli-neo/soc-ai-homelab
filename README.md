# AI SOC Automation Homelab

[![CI](https://github.com/samli-neo/soc-ai-homelab/actions/workflows/ci.yml/badge.svg)](https://github.com/samli-neo/soc-ai-homelab/actions/workflows/ci.yml)

Private SOC engineering portfolio that connects detection engineering, SOAR orchestration, threat intelligence, malware analysis, DFIR collection, case management, approval gates, and operational health checks into one controlled security-operations workflow.

This is not a toy dashboard or a single-vendor demo. It is a working homelab built to show how a SOC pipeline can ingest real telemetry, normalize alerts, enrich evidence, create cases, run safe automation, and keep high-risk response actions under human control.

## Executive Summary

| Area | What this project demonstrates |
| --- | --- |
| Detection engineering | Custom Wazuh decoders, rules, correlation logic, MITRE ATT&CK tagging, FIM, SCA, Syscollector, Windows Defender telemetry, pfSense, and Snort ingestion. |
| SOC automation | Shuffle workflow orchestration with semantic validation, digest routing, enrichment fan-out, case creation, DFIR collection, malware-analysis gates, and reporting. |
| Threat intelligence | MISP IOC matching for IPs, domains, and hashes, plus optional unpublished MISP event creation for analyst review. |
| Case management | TheHive deduplication, task ownership, quality gates, templates, dashboards, and controlled alert-to-case promotion. |
| Malware analysis | CAPEv2 lookup/detonation guardrails, CAPA/YARA/static triage, optional Ghidra escalation, and degraded-result handling when sandbox evidence is incomplete. |
| DFIR | Velociraptor read-only collection for mapped endpoints while isolation and destructive actions remain approval-gated. |
| Secure automation | Human approval gateway, Telegram approval workflow, audit-only action executor, per-agent identity model, and explicit kill switches. |
| Platform engineering | Docker Compose SOC stack, Proxmox-backed lab, CI validation, health checks, workflow watchdog, and operator dashboard services. |

## Architecture Preview

![AI SOC Automation Homelab portfolio preview](docs/assets/portfolio.png)

Editable diagrams are available for review and reuse:

- [Architecture diagram](docs/diagrams/soc-architecture.drawio)
- [Architecture SVG preview](docs/diagrams/soc-architecture.drawio.svg)
- [SOC role organigram](docs/diagrams/soc-workflow-organigram.drawio)
- [SOC role organigram SVG preview](docs/diagrams/soc-workflow-organigram.drawio.svg)

## SOC Workflow

```text
Telemetry sources
  Wazuh agents, Windows endpoint, pfSense syslog, Snort IDS, MISP IOC lists
        |
        v
Wazuh SIEM/XDR
  Custom decoders, custom rules, ATT&CK mapping, severity policy, correlation
        |
        v
SOC intake router
  Level < 9: digest path
  Level >= 9: full SOAR workflow
        |
        v
Shuffle SOAR workflow
  MISP enrichment -> Cortex analysis -> TheHive dedup/case/task creation
        |              |                 |
        |              |                 v
        |              |          Case quality gates
        |              v
        |       Analyzer evidence
        v
Velociraptor read-only DFIR
CAPEv2 + CAPA + YARA + optional Ghidra malware pipeline
IR AI advisor with approval constraints
Human approval gateway
Audit-only action executor
Reporting and SOC operations dashboard
```

## Core Design Principles

- Alerts should be normalized and scored before automation runs.
- Low-risk enrichment can run automatically; high-risk containment needs explicit human approval.
- Workflow success is not enough; node outputs are parsed for semantic failures.
- Malware analysis can be degraded or inconclusive, and the pipeline must say so clearly.
- Dedicated agent identities are preferred over shared admin credentials.
- Secrets and live credentials stay outside Git.
- The repository must remain reproducible enough for CI while preserving homelab-specific deployment details in documentation.

## Capability Map

| Capability | Implementation |
| --- | --- |
| SIEM/XDR | Wazuh manager, indexer, dashboard, centralized agent configuration, custom decoders, custom rules, MISP CDB lists. |
| Network security telemetry | pfSense filterlog and Snort CSV normalization with escalation rules for repeated or high-priority events. |
| Endpoint telemetry | Linux and Windows Wazuh agents with Syscollector, SCA, FIM, Windows Defender event channel, and hotfix inventory. |
| SOAR orchestration | Shuffle production workflow triggered by Wazuh through `custom-shuffle` and `soc-intake-router`. |
| Case management | `soc-thehive-deduper` creates or updates TheHive cases, assigns tasks, and prevents case floods. |
| Threat intel | `soc-misp-runner` enriches observables, handles IOC matches, and can create unpublished review events. |
| Analyzer execution | `soc-cortex-runner` runs or proposes Cortex analyzer jobs according to execution mode. |
| Malware pipeline | `soc-malware-pipeline-runner` coordinates CAPEv2, CAPA, YARA, static triage, artifact storage, and optional Ghidra escalation. |
| DFIR collection | `soc-velociraptor-runner` performs read-only collection from approved client mappings. |
| AI-assisted IR | `soc-ir-ai-advisor` produces constrained recommendations while forcing high-risk actions into approval flow. |
| Human approval | `soc-approval-gateway` records signed approval requests and can notify operators through Telegram. |
| Response execution | `soc-action-executor` records approved actions in `audit_only` mode until real adapters and rollback paths are implemented. |
| Operations | `soc-workflow-watchdog`, `soc-ops-dashboard`, and health scripts detect broken services, stuck workflows, and semantic failures. |

## Repository Map

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Main SOC service topology for the homelab reference stack. |
| `configs/wazuh-manager/` | Wazuh manager config, custom decoders/rules, MISP IOC lists, and centralized `agent.conf`. |
| `services/` | Internal Python/Node automation services used by Shuffle, Wazuh integrations, runners, approval flow, and dashboards. |
| `scripts/` | Deployment, regression, workflow E2E, malware VM operations, and SOC phase automation scripts. |
| `docs/soc/` | Integration notes, analyst playbooks, report templates, TheHive notes, and SOC operating documentation. |
| `docs/diagrams/` | Editable Draw.io architecture and role diagrams. |
| `dashboards/` | Dashboard specification artifacts. |
| `.github/` | CI, Dependabot, issue templates, PR template, and CODEOWNERS. |
| `docs/deployment.md` | Deployment, secrets, networking, and validation guide. |
| `docs/public-release-checklist.md` | Required safety checklist before making the private repo public. |

## Security Guardrails

- High-risk response actions are approval-gated by design.
- `soc-action-executor` defaults to `ACTION_EXECUTOR_MODE=audit_only` and records approved actions without changing firewalls, accounts, or endpoints.
- pfSense blocks, Snort rule changes, Velociraptor isolation, Wazuh active response, account disablement, broad collection, and sample detonation require explicit approval.
- Wazuh remote commands are intentionally not enabled in centralized agent configuration.
- Fresh malware detonation requires an explicit sample input, CAPE availability, sandbox readiness, and operator control.
- Secrets are loaded from local `.env` or service-specific env files that are ignored by Git.
- CI includes a high-risk literal secret scan to catch common accidental leaks.

## Validation

The repository includes checks for both portable review and live homelab validation.

Portable checks:

```bash
docker compose --env-file .env.example config --quiet
```

CI validates:

- Docker Compose syntax using a CI-safe generated Compose file.
- Python service compilation under `services/`.
- Wazuh XML fragments and Draw.io files.
- High-risk secret literal patterns.

Live homelab validation from the management workstation:

```powershell
powershell -ExecutionPolicy Bypass -File "scripts\test-soc.ps1" -SkipWazuhRegression
powershell -ExecutionPolicy Bypass -File "scripts\test-wazuh-pfsense-snort.ps1"
powershell -ExecutionPolicy Bypass -File "scripts\test-shuffle-workflow-e2e.ps1"
```

Wazuh deployment with regression:

```powershell
powershell -ExecutionPolicy Bypass -File "scripts\deploy-wazuh-config.ps1" -Restart -RunRegression
```

## Analyst Operating Model

The workflow models a small SOC with explicit responsibilities:

| Role | Responsibility |
| --- | --- |
| L1 triage | Validate alert context, run low-risk enrichment, and reduce noise. |
| L2 case manager | Deduplicate alerts, create cases, assign tasks, and enforce quality gates. |
| Threat intelligence analyst | Review MISP and Cortex enrichment and classify observable risk. |
| Malware analyst | Correlate CAPEv2, CAPA, YARA, Ghidra, and artifact evidence. |
| L3 DFIR analyst | Run approved read-only Velociraptor collection and prepare escalation evidence. |
| IR responder | Propose containment actions and wait for approval before execution. |
| CISO reporting | Produce operational and executive reporting from validated case evidence. |

## Running Locally

This project is a homelab reference architecture, not a turnkey cloud deployment.

1. Copy `.env.example` to `.env`.
2. Replace every `change-me` value with a unique secret.
3. Review absolute `/root/...` mounts in `docker-compose.yml` and adapt them to your lab host.
4. Create the external Docker network `vlan50` or adjust Compose networking for your environment.
5. Start the stack with Docker Compose.
6. Run validation scripts from the management workstation.

Detailed setup notes are in [`docs/deployment.md`](docs/deployment.md).

Before publishing this repository publicly, complete [`docs/public-release-checklist.md`](docs/public-release-checklist.md).

## Career Relevance

This project demonstrates hands-on ability across:

- SOC platform engineering and homelab operations.
- Detection engineering with Wazuh rules, decoders, CDB lists, and ATT&CK mapping.
- SOAR workflow design with Shuffle and semantic E2E validation.
- Case management with TheHive deduplication, task ownership, and quality gates.
- Threat intelligence workflows with MISP and Cortex.
- Malware-analysis orchestration with CAPEv2, CAPA, YARA, and Ghidra.
- DFIR automation with Velociraptor under read-only guardrails.
- Secure automation design with approval gates, audit-only execution, and least-privilege service identities.
- Infrastructure troubleshooting across Docker, Proxmox, pfSense, Windows sandbox VMs, and multiple security platforms.

## Roadmap

- Complete public-release security review and redact private operational notes.
- Replace remaining absolute homelab paths with more portable profiles.
- Expand ATT&CK-mapped detection tests and synthetic alert fixtures.
- Add richer dashboard examples with clean demo data.
- Add container linting and broader static checks.
- Package Wazuh validation as a reusable workflow.

## License

MIT. See [`LICENSE`](LICENSE).
