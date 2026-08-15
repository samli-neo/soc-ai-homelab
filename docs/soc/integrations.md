# SOC Integrations

## Event Flow

1. Wazuh collects and normalizes logs from agents, syslog, and custom decoders.
2. Wazuh rules assign severity, MITRE IDs, and SOC risk groups.
3. `custom-shuffle` sends level `7+` alerts to `soc-intake-router`.
4. `soc-intake-router` records level `<9` alerts for digest-only handling.
5. Level `>=9` alerts execute Shuffle workflow `043882e1-8ea3-4f88-898c-b12957ff2785`.
6. Shuffle calls TheHive dedup gate before case creation.
7. Shuffle can call low-risk execution services automatically and keeps high-risk response actions approval-gated.
8. n8n can consume approved business notifications or post-case workflow events from Shuffle.

## Agent Execution Policy

- Execution mode is controlled by `SOC_AGENT_EXECUTION_MODE`.
- `canary` is the current intended mode: low-risk actions may execute, high-risk containment remains approval-only.
- `propose_only` is the kill switch: Cortex runner returns proposed analyzer jobs without running them.
- `SOC_AUTO_EXECUTE_AGENTS` controls which agent profiles may auto-execute low-risk actions.
- Current low-risk auto-execution paths: Cortex analyzer jobs by `l1_triage`; TheHive alert/case/task creation by `l2_case_manager`; CAPEv2 hash/report lookup by `malware_analyst`; read-only Velociraptor collection by `l3_dfir`; digest recording by `ciso_reporting`.
- High-risk actions that still require human approval: pfSense blocks, Snort rule changes, Velociraptor isolation, Wazuh active response, account disablement, broad/destructive collection, and fresh sample detonation.
- Approved action execution path: `soc-action-executor` records approved high-risk actions in `audit_only` mode. It intentionally does not execute firewall/isolation/account actions until a per-action adapter is implemented and `ACTION_EXECUTOR_MODE=execute` is explicitly enabled.
- Per-agent credentials are supported by env vars such as `CORTEX_API_KEY_L1_TRIAGE` and `THEHIVE_API_KEY_L2_CASE_MANAGER`; until those are present, services report `credential_scope=fallback_shared` in their execution audit.
- Dedicated Cortex users created: `ai-l1-triage@lab.local`, `ai-threat-intel@lab.local`, `ai-malware-analyst@lab.local`.
- Dedicated MISP users created: `ai-soc-manager@lab.local`, `ai-l1-triage@lab.local`, `ai-l3-dfir@lab.local`, `ai-threat-intel@lab.local`, `ai-malware-analyst@lab.local`, `ai-detection-engineer@lab.local`, `ai-ir-responder@lab.local`, `ai-ciso-reporting@lab.local`.
- TheHive key auth is enabled in `/root/thehive-community-test/application.conf` with `auth.provider = [local, key, oauth2]`.
- Dedicated TheHive users created: `ai-soc-manager@lab.local`, `ai-l1-triage@lab.local`, `ai-l2-case-manager@lab.local`, `ai-l3-dfir@lab.local`, `ai-threat-intel@lab.local`, `ai-malware-analyst@lab.local`, `ai-detection-engineer@lab.local`, `ai-ir-responder@lab.local`, `ai-ciso-reporting@lab.local`.
- TheHive L2 automation uses dedicated user `ai-l2-case-manager@lab.local` through `THEHIVE_API_KEY_L2_CASE_MANAGER`; default `THEHIVE_API_KEY` is also set to the L2 key so case/alert writes are not admin-backed.
- Dedicated Velociraptor API clients created: `ai-l3-dfir` and `ai-dfir-agent`, both with role `reader`; configs are stored under `/root/soc-agent-credentials/velociraptor/` and must not be committed.
- Dedicated CAPEv2 user created: `ai-malware-analyst@lab.local`, non-staff and non-superuser, with DRF token stored in `/root/soc-agent-credentials/cape-agent-keys.env`.
- Dedicated Wazuh API users created: `ai-detection-engineer` and `ai-ir-responder`, both assigned built-in role `readonly`; credentials are stored in `/root/soc-agent-credentials/wazuh-agent-keys.env`.
- pfSense REST API user creation was not performed because common REST API paths returned `404`; pfSense containment remains proposal-only and approval-gated, using Wazuh telemetry for attribution until a supported pfSense API/user model is confirmed.

## TheHive

- Service: `soc-thehive-deduper`
- Endpoint: `POST http://soc-thehive-deduper:8080/case`
- Purpose: create one case per dedup key, update existing cases at controlled duplicate counts, prevent case floods.
- Agent identity: defaults to `l2_case_manager`; use `THEHIVE_API_KEY_L2_CASE_MANAGER` for dedicated attribution.
- Current TheHive writer identity: `AI L2 Case Manager` with roles `read, write, alert`.
- Required Wazuh fields: `rule.id`, `rule.level`, `rule.description`, `agent.name`, `location`, `data.srcip` when present.
- Native case templates created: `snort_ids`, `pfsense_firewall`, `malware_hash`, `authentication`, and `generic_wazuh`.
- Native dashboards created: `SOC Case Operations` and `SOC Alert Intake`, both shared dashboards with 3 rows and 9 widgets.
- Task ownership: the L2 case manager creates case tasks, but each task is assigned through TheHive 3 `owner` to the responsible AI duty owner. Current mapping includes L1 triage for evidence/timeline, Threat Intel for MISP/Cortex enrichment review, Detection Engineer for Snort validation, L3 DFIR for Velociraptor approval, Malware Analyst for malware/hash decisions, IR Responder for containment/firewall decisions, and L2 Case Manager for SLA acknowledgement, scoping, and closure.
- Task ownership validation: direct deduper validation case `2236` and full Shuffle execution `d7e3a6eb-9737-41ff-a8fe-7337e0dd08d0` / TheHive case `2237` both returned `task_owner` equal to the intended owner for all 7 generated generic tasks. Template branch validation also passed: Snort case `2238` assigned `Validate Snort IDS signature and priority` to `ai-detection-engineer@lab.local`, and malware hash case `2239` assigned `Malware/hash analysis decision` to `ai-malware-analyst@lab.local`.
- Native case report templates were researched but not created because live TheHive 3.5.2 Community does not expose the TheHive 5 Platinum `manageCaseReportTemplate` API/feature; the Markdown report templates under `docs/soc/reports/` remain the supported report source.
- Implementation note: live TheHive is 3.5.2, so dashboard definitions are stored as JSON strings, TheHive 5-only fields such as case-template `displayName` are not used, and TheHive 5 case-report-template docs do not map to this deployment. See `docs/soc/thehive-templates-dashboards.md`.
- Duplicate native Alert handling: TheHive Alert creation can return a version-conflict duplicate for an existing `sourceRef`; `soc-thehive-deduper` treats that as non-fatal and continues case/task handling instead of returning `/case` 502.
- Case quality gates: new cases include `soc_quality_gates`, `quality-gated` tags, and a task named `Quality gate: verify evidence before closure`. Required gates cover source alert, asset context, triage score, MISP/Cortex enrichment, IR recommendation, human approval status, and final disposition.

## Cortex

- Role: analyzer execution and observable enrichment.
- Agent identity: defaults to `l1_triage`; use `CORTEX_API_KEY_L1_TRIAGE` for dedicated attribution.
- Recommended use: run analyzers from TheHive or Shuffle after case creation, not directly from low-level Wazuh noise.
- Guardrail: analyzer failures should enrich the case but must not block containment decisions.

## CAPEv2

- Role: automated malware hash search and CAPEv2 report lookup.
- Agent identity: `ai-malware-analyst@lab.local` through `CAPEV2_API_KEY_MALWARE_ANALYST` in the live credential vault.
- Current permission shape: regular Django user plus DRF token, not staff and not superuser.
- Service: `soc-capev2-runner`.
- Endpoint: `POST http://soc-capev2-runner:8080/analyze`; health endpoint: `GET /health`.
- Persistence: Compose-managed in local/live `docker-compose.yml` with env file `/root/soc-capev2-runner/env`.
- CAPEv2 is now called through `soc-malware-pipeline-runner` from workflow node `soc-capev2-agent-0006`; the direct runner still returns `executed_actions=["cape_hash_search", "cape_report_lookup"]` for hash-bearing alerts when called by the orchestrator.
- Sandbox target: CAPE physical machine `win11` at `10.10.50.103`, backed by Proxmox VM `103` / `sandbox-WIN11`.
- Detonation support: the runner can submit `sample_url` or `sample_path` to CAPE when `CAPE_ALLOW_SAMPLE_DETONATION=true`, but it first verifies the sandbox agent port is reachable.
- CAPEv2 availability gate: the runner checks CAPE API reachability before hash lookup or sample submission. If VM `111` / `CAPE` is stopped or the API is unreachable, the runner returns `status=cape_api_unreachable` and the workflow records degraded analysis instead of silently treating the sample as benign.
- Detonation report gate: fresh sample submissions are polled until CAPE reaches `reported` or the configured timeout. Reported task summaries are included in the pipeline verdict and IOC extraction.
- Detonation quality settings: submissions use configurable runtime fields `CAPE_ANALYSIS_TIMEOUT_SECONDS` (default `300`), `CAPE_POLL_TIMEOUT_SECONDS` (default `CAPE_ANALYSIS_TIMEOUT_SECONDS + 180`), `CAPE_ANALYSIS_PACKAGE` (default `exe`), `CAPE_ANALYSIS_ROUTE` (default `none`), `CAPE_ANALYSIS_OPTIONS`, and `CAPE_ENFORCE_TIMEOUT`. The runner records the safe submission fields in output for auditability.
- Analysis-log fallback: when CAPE raw monitor logs are absent, `soc-capev2-runner` fetches CAPE's official `tasks/get/report/<task_id>/all/` zip and summarizes `analysis.log` process execution, monitor injection, resume, warning, and error lines as `analysis_log_summary`.
- Failed report handling: reported tasks with CAPE `malstatus=Failed`, report fetch errors, or CAPE submission responses with no task IDs are explicitly represented as degraded/inconclusive conditions. Failed submissions are no longer counted as successful detonations.
- Repeat detonation note: CAPE's `[uniq_submission]` gate in `/opt/CAPEv2/conf/web.conf` was disabled for the sandbox so controlled repeat detonations of the same hash can create new tasks instead of returning `Error adding task to database`.
- Sandbox Defender note: VM `103` / `sandbox-WIN11` has Defender disabled by offline policy for malware detonation quality. Rollback snapshot before this change: `pre-defender-disable-20260814`.
- Known remaining CAPE gap: Tyupkin tasks `19`, `21`, `22`, `24`, and `25` proved the sample launches and the 32-bit CAPE monitor is injected/attempted, but CAPE still emits no `.bson` API-call behavior for this PE32 .NET sample and returns degraded/failed behavior. Treat this as a CAPE monitor/32-bit-.NET coverage issue, not a Defender block; use `analysis_log_summary` as degraded dynamic telemetry until 32-bit monitor capture is fixed or an x86/.NET-compatible sandbox is added. Task `22` tested temporary runner option `no-iat=1`; CAPE logged `IAT patching disabled` but still used queued APC for the .NET sample and produced no monitor initialization, so `no-iat=1` is not a fix. Tasks `23`/`24` tested a temporary `exe_nosuspend` package to avoid suspended startup; task `23` was invalid due a stale `.exe` rename collision, and task `24` still produced no `.bson` while the loader logged `InjectDllViaQueuedAPC: Failed to allocate buffer in target: Access is denied`. VM `103` inspection showed .NET 3.5/CLR v2 and CLR v4 are enabled, VC80 runtime files exist, and `CorFlags.exe` is missing. CAPE `exe.py` now has a Python fallback for `runasx86=1` to set `COMIMAGE_FLAGS_32BITREQUIRED` without `CorFlags.exe`; task `25` confirmed this removes the CorFlags blocker, but CAPE's compiled loader still uses the `.NET` queued-APC path and produces no `.bson`.
- VM `103` CAPE agent: `C:\CAPE\agent.py` runs under 32-bit Python at `C:\Python312-32\python.exe` through the `CAPE Agent` startup scheduled task, with working directory `C:\CAPE`; port `8000` is reachable and sample URL submission was validated with CAPE task `16`.
- Guardrail: fresh sample upload/detonation is automatic only when explicitly requested by `sample_url` or `sample_path` and the sandbox agent is ready; it does not fabricate samples or submit without an input.

### Malware Detonation VM Runbook

- Before any live sample detonation, start Proxmox VM `111` / `CAPE` and VM `103` / `sandbox-WIN11`.
- Operator script: use `powershell -ExecutionPolicy Bypass -File "scripts\malware-vm-ops.ps1" -Action Start` before detonation, `-Action Status` to confirm state, and `-Action Shutdown` after work is complete.
- Confirm CAPE API is reachable at `https://10.10.50.102/apiv2/tasks/list/?limit=1&offset=0` from the SOC Docker network.
- Confirm the sandbox agent is reachable at `10.10.50.103:8000`; RDP `3389` being open is not enough for detonation readiness.
- Create a rollback snapshot of VM `103` before real malware detonation.
- Submit only samples staged under `/samples` or controlled URLs explicitly requested by the analyst workflow.
- After validation or detonation work is complete, shut down VM `111` / `CAPE` and VM `103` / `sandbox-WIN11` unless continued analysis is intentionally required.
- Treat `benign_or_unknown` with CAPE API unreachable, unreported tasks, or `cape_reported_no_behavior_inconclusive` as incomplete analysis, not a clean verdict. `cape_analysis_log_dynamic_signal` means CAPE observed analyzer process execution/injection in `analysis.log`, even if API-call monitor behavior is absent.

## Ghidra

- Role: controlled static malware analysis and L2/L3 reverse-engineering escalation for the Malware Analyst agent.
- Agent identity: `malware_analyst`; service responses include `execution_audit.agent_id=malware_analyst`.
- Service: `soc-ghidra-runner`.
- Endpoint: `POST http://soc-ghidra-runner:8080/analyze`; health endpoint: `GET /health`.
- Intended malware analysis architecture: `hash/YARA/CAPA static triage -> CAPEv2 dynamic sandbox/report lookup -> payload/report correlation -> conditional Ghidra Headless escalation -> AI Malware Analyst correlation`.
- External MCP bridge: project `opencode.jsonc` registers local MCP server `soc-ghidra-malware-analysis`, which exposes `ghidra_health`, `ghidra_static_analyze`, and `malware_static_pipeline`, and points to `http://10.10.50.111:18080`.
- Persistence: Compose-managed in local/live `docker-compose.yml` with env file `/root/soc-ghidra-runner/env`; samples are stored under `/root/soc-ghidra-runner/samples` and mounted as `/samples`; temporary projects use `/root/soc-ghidra-runner/work` mounted as `/work`; YARA rules are mounted from `services/soc-ghidra-runner/rules` to `/rules`.
- Current safe operations: CAPA JSON analysis with official `capa-rules`, optional Ghidra headless import/analyze, YARA scan with SOC rules, `file` metadata, `strings` preview, and `objdump -x` preview for `sample_path` under `/samples` or HTTP(S) `sample_url`. `run_ghidra=true` must be passed explicitly by the orchestrator or analyst tooling; default static triage skips Ghidra.
- Output for the AI Malware Analyst: `ioc_candidates`, `ttp_candidates`, `suspicious_functions`, YARA matches, CAPA capabilities, Ghidra status, and a heuristic pre-verdict. The pre-verdict is evidence triage, not a final autonomous malicious/benign decision.
- Guardrail: the malware analyst receives a constrained API/MCP tool, not arbitrary shell access. Sample size, timeout, and output size are bounded by env vars.

## Malware Pipeline Runner

- Role: orchestrate the malware-analysis chain without putting all logic inside CAPEv2 or Ghidra.
- Service: `soc-malware-pipeline-runner`.
- Endpoint: `POST http://soc-malware-pipeline-runner:8080/analyze`; health endpoint: `GET /health`.
- Read endpoints: `GET /jobs/<job_id>` returns compact job status; `GET /artifacts/<artifact_id>` returns the full stored analysis JSON.
- Persistence: Compose-managed in local/live `docker-compose.yml`; local source is `services/soc-malware-pipeline-runner/app.py`; full analysis artifacts are stored under `/root/soc-malware-pipeline-runner/artifacts` and mounted as `/artifacts`.
- Workflow node `soc-capev2-agent-0006` is labeled `AI Malware Analyst - Malware Pipeline Orchestrator` and calls this service automatically.
- Shuffle node output is intentionally compact: the full orchestrator response can exceed Shuffle result-size limits, so the workflow stores verdict, actions, guardrails, IOC/TTP/function summaries, CAPEv2 summary, static status, and Ghidra skip/escalation state instead of full CAPA/objdump/Ghidra details.
- Current orchestration: calls `soc-capev2-runner` for hash/report lookup and guarded sample submission, calls `soc-ghidra-runner` first with `run_ghidra=false` for CAPA/YARA/static triage, then calls it again with `run_ghidra=true` only when `force_ghidra=true` or the static triage score reaches `GHIDRA_ESCALATION_SCORE` (default `70`).
- CAPE scoring: completed detonation task reports are now included in verdict scoring; high CAPE malscore or alert signatures raise the verdict. When raw CAPE behavior is empty, `analysis_log_summary` execution/injection counts are counted separately as `analysis_log_signal_count` and add verdict reason `cape_analysis_log_dynamic_signal`; only reports with no signatures, no network/file indicators, and no analysis-log signal are marked `cape_reported_no_behavior_inconclusive`.
- Output for the AI Malware Analyst: combined verdict, CAPEv2 summary, static triage result, optional Ghidra escalation result, IOC candidates, TTP candidates, suspicious functions, execution audit, and explicit guardrails.
- Each analysis receives a `job_id` and `artifact_id`; compact outputs include those IDs so analysts can retrieve full evidence outside Shuffle.
- Guardrail: containment actions are not executed; fresh detonation remains controlled by `soc-capev2-runner` env and sandbox readiness; Ghidra is escalation-only by default.
- E2E validation: synthetic rule `100513` with `/samples/benign-ls` created Shuffle execution `efb72742-9b08-486b-bbec-62aa5ad49630`, finished `FINISHED` at `soc-reporting-0010`, and malware node output reported `status=malware_pipeline_completed`, actions `cape_hash_search`, `cape_report_lookup`, `capa_analyze`, `yara_scan`, verdict `suspicious` score `60`, and `ghidra_skipped=true` with reason `run_ghidra_not_requested`.

## Velociraptor

- Role: automated read-only DFIR collection for mapped endpoints.
- Agent identities: `ai-l3-dfir` and `ai-dfir-agent` API client configs in `/root/soc-agent-credentials/velociraptor/`.
- Current permission shape: Velociraptor `reader` role.
- Service: `soc-velociraptor-runner`.
- Endpoint: `POST http://soc-velociraptor-runner:8080/collect`; health endpoint: `GET /health`.
- Persistence: Compose-managed in local/live `docker-compose.yml` with env file `/root/soc-velociraptor-runner/env`.
- Workflow node `soc-velociraptor-0005` calls the runner automatically. Current safe artifact allowlist: `Generic.Client.Info`, `Windows.System.Pslist`, and `Windows.Network.Netstat`.
- VM `103` note: Velociraptor client `C.d8a596ff70205a65` is mapped through `VELO_CLIENT_SANDBOX_ID`; `sandbox-WIN11`, legacy `Win11pro`, and sandbox alerts map with reason `sandbox_agent_name`, and validated read-only collection returns success.
- Guardrail: read-only collection is automatic for mapped clients; endpoint isolation, destructive collection, broad acquisition, and service/control actions remain approval-gated.

## Wazuh

- Role: detection engineering visibility and IR telemetry over agents, including pfSense and EDR events.
- Agent identities: `ai-detection-engineer` and `ai-ir-responder` with Wazuh API role `readonly`.
- Current validated safe call: `GET /agents?limit=1` returns HTTP `200` for both users.
- Centralized agent config: `configs/wazuh-manager/agent.conf` deploys to `/var/ossec/etc/shared/default/agent.conf` and is bind-mounted from `/root/soc-configs/wazuh-manager/agent.conf` for container recreation persistence.
- Endpoint coverage: Linux agents receive Syscollector, SCA, and FIM over core OS paths; Windows agents receive Syscollector including hotfixes, SCA, FIM over startup/hosts paths, and Windows Defender Operational eventchannel collection.
- Malware/FIM threat intelligence: `configs/wazuh-manager/misp_ioc_rules.xml` rules `100205` and `100206` match `syscheck.sha256_after` from file-add/file-modify alerts against `etc/lists/misp_hash_iocs`.
- Deployment: use `powershell -ExecutionPolicy Bypass -File "scripts\deploy-wazuh-config.ps1" -Restart -RunRegression`; the script validates Wazuh rules before restart, backs up changed files under `/var/ossec/etc/soc-deploy-backups/<deploy-id>`, and restores backups on validation failure.
- Last validated Wazuh deploy: deploy ID `20260815-121713`; Wazuh analysisd validation passed without warnings; pfSense/Snort regression evidence `./wazuh-test-evidence/20260815-122936-wazuh-pfsense-snort-tests.txt`; full SOC health passed with `scripts\test-soc.ps1 -SkipWazuhRegression`.
- Guardrail: active response and rule/config changes remain approval-gated and are not granted to these users.
- Guardrail: Wazuh remote commands are intentionally not enabled in centralized agent config.

## MISP

- Rules: `configs/wazuh-manager/misp_ioc_rules.xml`
- Lists: `configs/wazuh-manager/misp_ip_iocs`, `misp_domain_iocs`, `misp_hash_iocs`
- Output groups: `threat_intel`, `misp`, `soc_risk_high`, `soc_risk_critical`, `incident_candidate`.
- Routing: MISP hash matches are critical; IP/domain matches are high unless suppressed by an allowlist process.
- Service: `soc-misp-runner`
- Endpoint: `POST http://soc-misp-runner:8080/triage`; health endpoint: `GET /health`.
- Persistence: Compose-managed in local/live `docker-compose.yml` with env file `/root/soc-misp-runner/env`.
- Agent identity: defaults to `l1_triage` and uses `MISP_API_KEY_L1_TRIAGE` for IOC enrichment.
- SOC event writer: when `MISP_EVENT_WRITES_ENABLED=true`, `/triage` creates an unpublished local MISP event for alerts at or above `MISP_EVENT_WRITE_MIN_LEVEL` when extracted observables are not already in MISP. Event creation uses `MISP_EVENT_WRITE_AGENT_ID` (currently `threat_intel`) and stays unpublished for analyst review.
- Workflow node `soc-triage-misp-0002` calls the runner through Shuffle Tools Python so MISP searches are attributable to the L1 agent, not the old shared Shuffle app auth.

## Shuffle

- Wazuh hook target: `http://soc-intake-router:8080/intake`
- Intake router metrics: `GET http://soc-intake-router:8080/metrics` returns in-memory routing counters for total intakes, digest-only routes, full-workflow forwards, errors, route reasons, rule IDs, and the last routing decision.
- Workflow watchdog: `GET http://soc-workflow-watchdog:8080/metrics` checks recent production workflow executions for stuck `EXECUTING` runs, failed runs, and finished executions with fewer than the expected 10 node results.
- Semantic workflow watchdog: the watchdog also parses inner node JSON and reports `semantic_failed_count` / `semantic_warning_count`, catching green Shuffle nodes that contain inner failures.
- SOC ops dashboard: `GET http://soc-ops-dashboard:8080/dashboard` renders an operator dashboard, and `/metrics` aggregates intake, workflow watchdog, approval gateway, action executor, and core runner health.
- Workflow E2E regression: run `powershell -ExecutionPolicy Bypass -File "scripts\test-shuffle-workflow-e2e.ps1"` to submit a safe L10 alert through `soc-intake-router`, poll Shuffle until finished, and assert all 10 SOC nodes succeeded. The script also parses inner node JSON and fails on wrapped semantic failures such as `success=false`, `shuffle_python_node_error`, `agent_contract_unavailable`, or inner `error` fields. This creates safe validation evidence in MISP/TheHive and does not detonate malware or execute containment.
- Queue hygiene: if fresh E2E executions stay `EXECUTING` with `result_count=0`, inspect `workflowqueue-shuffle`, `workflowexecution-000001`, `shuffle-backend`, and `shuffle-orborus` before changing node code. Stale queue documents can keep Orborus rerunning old executions and trigger Shuffle CE app-run quota pressure. Back up queue/execution documents before cleanup.
- Last validated workflow E2E: execution `1c835f46-d48b-4856-a293-405061d262af` completed with 10/10 nodes; only warning was expected `cape_api_unreachable` while CAPE VM `111` was intentionally stopped.
- Workflow: `SOC Security Operations - Wazuh Triage and Response v1`
- Workflow ID: `043882e1-8ea3-4f88-898c-b12957ff2785`
- Workflow status: `production`; tags include `production-soc`, `workflow-v1`, `human-approval-gated`, and `audit-only-containment`.
- Required behavior: enrichment, TheHive case/task creation, CAPEv2 hash/report lookup, and read-only Velociraptor collection can run automatically; isolation, firewall changes, sample detonation, and destructive actions require approval.
- Synchronization: the workflow starts with `soc-orchestrator-0001`, fans out to MISP and Cortex, converges at TheHive, fans out to Velociraptor and CAPEv2, then continues through Threat Intel, pfSense/IR proposal, human approval contract, and CISO reporting.
- MISP synchronization note: `soc-triage-misp-0002` must parse whole `$exec` as `raw_execution_argument` and call `soc-misp-runner`; do not use explicit `$exec.data.*` interpolation because Shuffle can render missing-dollar literals such as `.data.srcip`.
- Workflow credential hygiene: API-key workflow variables are intentionally blank. Runtime credentials live in internal service env files such as `/root/soc-misp-runner/env`, `/root/soc-cortex-runner/env`, and `/root/soc-thehive-deduper/env`.

## IR AI Advisor

- Service: `soc-ir-ai-advisor`
- Endpoints: `GET /health`, `GET /agents`, `POST /agent`, and backward-compatible `POST /advise`.
- Persistence: Compose-managed in local/live `docker-compose.yml` with env file `/root/soc-ir-ai-advisor/env`.
- OpenRouter model routing uses `OPENROUTER_MODEL` first, then comma-separated `OPENROUTER_FALLBACK_MODELS`; if all model calls fail, deterministic safe advice is returned.
- The advisor reports sanitized `ai_model`, `ai_model_attempts`, and `ai_fallback_errors` metadata without exposing API keys or response bodies.
- Guardrail: model output is post-processed so high-risk actions still require human approval and `executed_actions` is always forced to `[]`.

## Approval Gateway

- Service: `soc-approval-gateway`.
- Endpoints: `GET /health`, `POST /approval/request`, `GET /approval/<request_id>`, and `POST /telegram/webhook`.
- Persistence: Compose-managed in local/live `docker-compose.yml`; SQLite state is stored under `/root/soc-approval-gateway/data` and mounted as `/data`.
- Purpose: create a durable approval record for high-risk SOC actions and notify a human through Telegram without letting Telegram or n8n execute actions directly.
- Current high-risk action allowlist: `pfsense_block`, `snort_rule_change`, `velociraptor_isolate`, `wazuh_active_response`, `account_disable`, and `sample_detonation`.
- Telegram controls: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_ALLOWED_CHAT_IDS`, `TELEGRAM_ALLOWED_USER_IDS`, `TELEGRAM_WEBHOOK_SECRET`, and `APPROVAL_SIGNING_SECRET` live in `/root/soc-approval-gateway/env` and must not be committed.
- Live path note: `/root/soc-approval-gateway/env` is inside LXC `200` (`soc-docker`), not the Proxmox host filesystem.
- Callback safety: inline button callbacks are HMAC-signed, checked against allowlisted chat/user IDs, and rejected after TTL expiry or prior decision.
- Approval message UX: Telegram messages use an operator-facing template with severity, action, case, request ID, target, reason, risk, evidence, and an explicit `audit_only` reminder.
- Callback transport: `POST /telegram/webhook` is available for a public Telegram webhook, and the service also runs Telegram long polling by default (`TELEGRAM_POLLING_ENABLED=true`) for homelab deployments without a public callback URL.
- Telegram callback data must stay under Telegram's 64-byte limit. Shuffle-generated approval request IDs should be short, for example `apr-pfsenseblo-999992-79133`, otherwise Telegram returns `BUTTON_DATA_INVALID` and no inline buttons are sent.
- Execution safety: default `APPROVAL_EXECUTION_MODE=audit_only`; even approved requests do not execute firewall/isolation actions unless `APPROVAL_EXECUTION_MODE=execute` and `ACTION_EXECUTOR_URL` are explicitly configured.
- Shuffle integration: live workflow `043882e1-8ea3-4f88-898c-b12957ff2785` node `soc-ir-approval-0009` calls `POST http://soc-approval-gateway:8080/approval/request` for high-risk IR recommendations. The gateway sends Telegram approval, records the decision, and later a separate action executor can handle approved actions if execution mode is explicitly enabled.

## Action Executor

- Service: `soc-action-executor`.
- Endpoints: `GET /health`, `GET /metrics`, and `POST /<action>` for allowed high-risk action names.
- Current mode: `ACTION_EXECUTOR_MODE=audit_only`; approved action attempts are persisted under `/root/soc-action-executor/data/actions.sqlite3` and return `executed=false`.
- Allowed action names: `pfsense_block`, `snort_rule_change`, `velociraptor_isolate`, `wazuh_active_response`, `account_disable`, and `sample_detonation`.
- Guardrail: `execute` mode currently returns `execute_mode_not_implemented` until real per-action adapters and rollback paths are deliberately added.

## n8n

n8n should be a downstream automation layer, not the primary incident-response authority.

Recommended n8n webhook contract:

```json
{
  "source": "shuffle",
  "event_type": "soc_case_update",
  "severity": "high",
  "risk_group": "soc_risk_high",
  "case_id": "THEHIVE_CASE_ID",
  "title": "Wazuh alert title",
  "mitre": ["T1078"],
  "approval_required": true,
  "executed_actions": [],
  "recommended_actions": ["Investigate source host", "Check related alerts"]
}
```

n8n workflows should handle manager notifications, SLA reminders, ticket synchronization, and weekly reporting. They should not directly isolate hosts or change firewall policy.
