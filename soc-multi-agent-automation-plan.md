# Multi-Agent SOC Automation Plan
### Stack: Shuffle (orchestration) · Wazuh (SIEM/EDR) · TheHive (case management) · MISP (threat intel) · Cortex (enrichment) · CAPEv2 (sandbox) · Velociraptor (DFIR)

---

## 1. Architecture Overview

```
Wazuh (detection) → Shuffle (orchestrator) → Agent Pool → TheHive (cases) → Human analyst (when needed)
                                    ↕
                    MISP / Cortex / CAPEv2 / Velociraptor (tools each agent calls)
```

- **Shuffle is the nervous system.** Every agent is implemented as a Shuffle workflow (or a sub-workflow called by the orchestrator) that wraps an LLM call plus deterministic app actions (Wazuh API, TheHive API, MISP API, Cortex API, CAPEv2 API, Velociraptor API/VQL).
- **LLM calls are used for judgment, not for plumbing.** Anything deterministic (querying an API, formatting a case, updating a field) should be a plain Shuffle app action. The LLM is invoked only where a decision, summary, or hypothesis is required.
- **Every agent writes its output to TheHive** as a case, task, or observable — this becomes the shared memory across agents, so no agent needs to hold long conversational context.

---

## 2. Agent Roster

| # | Agent | Human role modeled | Trigger | Primary tools |
|---|-------|--------------------|---------|----------------|
| 0 | Orchestrator | SOC Manager | Every Wazuh alert / scheduled cron | Shuffle only |
| 1 | Triage Agent | Analyst Tier 1 | New Wazuh alert | Wazuh, MISP, Cortex |
| 2 | Investigation Agent | Analyst Tier 2 | Case opened by Triage Agent | TheHive, Wazuh, Velociraptor |
| 3 | Malware Analysis Agent | Malware specialist | Suspicious file/hash found | CAPEv2, MISP |
| 4 | Threat Intel Agent | CTI Analyst | Scheduled + MISP feed webhook | MISP, Cortex, Wazuh (rule push) |
| 5 | Threat Hunting Agent | Analyst Tier 3 | Scheduled (e.g. nightly) | Velociraptor, MISP, Wazuh |
| 6 | Incident Response Agent | IR Lead | Case marked "confirmed incident" | Velociraptor, Wazuh (active response), TheHive |
| 7 | Reporting/QA Agent | SOC Manager (reporting function) | Case closed | TheHive, MISP |

---

## 3. Agent 0 — Orchestrator

**Role:** routes events to the right sub-agent, tracks SLAs, and is the only agent allowed to hand a case to a human.

**Logic:**
1. Listens to Wazuh webhook (or polls Wazuh API every N seconds) for new alerts above a severity threshold.
2. Applies a deterministic pre-filter (dedup, known noisy rule IDs suppressed) — this is a plain Shuffle condition, no LLM.
3. Sends the alert payload to the **Triage Agent** sub-workflow.
4. Reads the Triage Agent's verdict (JSON) and branches:
   - `false_positive` → close silently, log for tuning.
   - `monitor` → tag and store, no case created.
   - `investigate` → create TheHive case, call **Investigation Agent**.
   - `critical` → create TheHive case with high severity, call **Investigation Agent** AND pre-stage **Incident Response Agent** on standby.
5. Enforces SLA timers (e.g. Investigation Agent must return within 15 min or the case auto-escalates to a human).

**Output contract passed downstream (JSON):**
```json
{
  "alert_id": "string",
  "source": "wazuh",
  "severity": "low|medium|high|critical",
  "verdict": "false_positive|monitor|investigate|critical",
  "case_id": "thehive_case_id_or_null",
  "reasoning": "short justification string"
}
```

---

## 4. Agent 1 — Triage Agent (Tier 1)

**Status:** Phase 1 complete on 2026-07-12. `scripts/phase1-triage-orchestrator.ps1` and `samples/phase1-wazuh-alert-misp-hash.json` are added. The runner normalizes Wazuh alerts, enriches observables through MISP, returns strict JSON routing, supports optional OpenRouter with deterministic fallback, and creates TheHive cases when required. Final verification found 1 true MISP SHA-256 match, classified the sample as `critical`, and created TheHive case number `9` (`lzVkWZ8BMJtAHxh0MJkP`).

**Goal:** decide, in under a couple of minutes, whether an alert is noise or worth a human/agent's time.

**Workflow steps:**
1. Extract observables from the Wazuh alert (IP, domain, hash, user, host).
2. For each observable, query **MISP** for existing attributes/events (has this IOC been seen before, in which campaign).
3. Run **Cortex** analyzers on each observable (VirusTotal, AbuseIPDB, GeoIP, WHOIS — whichever are configured).
4. Feed the alert + MISP context + Cortex results to the LLM with a strict system prompt:
   - Task: classify as `false_positive`, `monitor`, `investigate`, or `critical`.
   - Constraint: must justify with reference to specific enrichment data, not just the raw alert text.
   - Output: strict JSON only (no prose) so Shuffle can parse it reliably.
5. If verdict is `investigate` or `critical`, create a TheHive alert → case, attach all observables and enrichment as case observables.

**Example LLM system prompt skeleton:**
```
You are a Tier 1 SOC analyst. You will receive a Wazuh alert plus MISP and Cortex
enrichment data. Classify the alert into exactly one of:
false_positive, monitor, investigate, critical.
Base your decision only on the provided data. Do not invent context.
Respond with JSON only: {"verdict": "...", "confidence": 0-1, "reasoning": "..."}
```

**Failure mode handling:** if MISP/Cortex enrichment times out, the agent still classifies using the raw alert only, but caps the verdict at `monitor` (never `false_positive`) to avoid silently dropping something it couldn't check.

---

## 5. Agent 2 — Investigation Agent (Tier 2)

**Status:** Phase 2 executable runner verified on 2026-07-11. `scripts/phase2-investigation.ps1 -Target windows -CreateTheHiveCase` collected 573 Velociraptor events from Windows client `C.2e2927748d64c9de` and created TheHive case number `2`.

**Goal:** build the full picture of what happened on the affected host/user before a human or the IR agent gets involved.

**Workflow steps:**
1. Pull the TheHive case created by the Triage Agent.
2. Query Wazuh for historical alerts on the same host/user (last 7–30 days) to spot a pattern rather than an isolated event.
3. Trigger a **Velociraptor** collection on the affected endpoint:
   - Process tree, autoruns/persistence artifacts, network connections, recently modified files.
   - Use pre-built VQL artifacts (`Windows.System.Pslist`, `Windows.Persistence.*`, `Generic.Client.Info`, etc.).
4. If a suspicious file/hash is found in the Velociraptor results → hand off to **Malware Analysis Agent**, wait for its verdict before finalizing.
5. LLM synthesizes: Wazuh history + Velociraptor artifacts + malware verdict (if any) into:
   - An incident narrative (plain English timeline).
   - A classification: `benign_confirmed`, `needs_human_review`, or `confirmed_incident`.
6. Updates the TheHive case with the narrative, evidence, and classification; adds tasks for a human analyst if `needs_human_review`.
7. If `confirmed_incident` → hands off to **Incident Response Agent**.

---

## 6. Agent 3 — Malware Analysis Agent

**Status:** Phase 3 complete on 2026-07-11. `scripts/phase3-malware-analysis.ps1` and `shuffle/malware-analysis-agent-capev2.md` are added. Existing CAPEv2 task `12`, SHA-256 lookup for `824a9641bcf64f711ba98108ee463075af8047d19e6f72aca761f4e0035fc8c2`, fresh file submission, TheHive case creation, and MISP event creation are verified.

**Goal:** determine whether a file/hash is malicious and extract fresh IOCs.

**Workflow steps:**
1. Receive file or hash from Investigation Agent (or directly from Wazuh FIM/EDR events).
2. Submit to **CAPEv2** for detonation.
3. Poll for the CAPEv2 report; parse behavioral indicators (network calls, registry changes, process injection, dropped files).
4. LLM summarizes the report into a verdict (`malicious`, `suspicious`, `benign`) with a short behavioral rationale — useful because raw sandbox reports are long and noisy.
5. Any new IOCs (C2 domains, dropped-file hashes, mutexes) are pushed automatically into **MISP** as a new event, tagged with the source case ID for traceability.
6. Returns verdict + IOC list to the calling agent (Investigation Agent or Orchestrator).

---

## 7. Agent 4 — Threat Intelligence Agent

**Status:** Phase 4 complete on 2026-07-12. `scripts/phase4-threat-intel.ps1` and `shuffle/threat-intel-agent-misp-wazuh.md` are added. MISP attribute pull, Wazuh IOC list/rule artifact generation, Wazuh deployment, config validation, manager restart, and custom IOC rule-match proof are verified. The Phase 3 MISP SHA-256 IOC from event `1` fires Wazuh rule `100204` in `wazuh-logtest-legacy`.

**Goal:** keep detection content and context current, independent of any single alert.

**Two trigger modes:**
- **Scheduled** (e.g. every hour): pull new/updated MISP events from subscribed feeds.
- **Event-driven**: triggered whenever the Malware Analysis Agent or Investigation Agent pushes new IOCs into MISP.

**Workflow steps:**
1. Pull new MISP events/attributes since last run.
2. Run Cortex analyzers on new IOCs to validate/enrich before they're trusted (avoid propagating bad intel).
3. LLM step: decide which new indicators are relevant to this organization's threat profile (industry, geography, prior incidents) vs. generic noise — outputs a filtered, prioritized list.
4. For relevant indicators, generate/update Wazuh detection content (e.g. custom rules or a blocklist decoder) and push via the Wazuh API or config management.
5. Log a short daily/weekly digest of what changed (new actors, new IOCs, new detections added) — this becomes input for the Reporting Agent.

---

## 8. Agent 5 — Threat Hunting Agent (Tier 3)

**Status:** Phase 6 complete on 2026-07-12 for the read-only hunt layer. `scripts/phase6-threat-hunt.ps1` and `shuffle/threat-hunting-agent-velociraptor.md` are added. Windows Velociraptor hunt, MISP IOC context checks, evidence output, TheHive case creation, and TheHive read-back are verified. The first verified hunt collected 572 events from `BOSGAME-W7TSE`, found 1 low-severity PowerShell lead, and found 0 high/medium hits.

**Goal:** proactively look for what automated detections missed.

**Workflow steps:**
1. Runs on a schedule (e.g. nightly or weekly), not on alerts.
2. LLM generates 3–5 hunting hypotheses per run, based on:
   - Recent MISP campaign/TTP updates.
   - Gaps identified from closed cases (things that were *found* by Investigation Agent but not by Wazuh rules).
3. Translates hypotheses into **Velociraptor VQL** queries run fleet-wide (not just one host), e.g. hunting for a specific persistence technique or LOLBin usage pattern.
4. Any hits are packaged into a new TheHive case with full context (hypothesis, query used, hosts affected) and routed back through the Orchestrator as if it were a fresh alert — so it goes through Investigation Agent / IR Agent normally.
5. Hypotheses that returned nothing are logged too — this is useful hunting history, not wasted effort.

---

## 9. Agent 6 — Incident Response Agent

**Status:** Phase 5 started on 2026-07-12. `scripts/phase5-incident-response.ps1` and `shuffle/incident-response-agent-approval.md` are added. Proposal-only response planning, approval-token guardrail, blocked execution without approval, TheHive approval case creation, and TheHive read-back are verified. Live containment adapters are intentionally disabled until a safe Velociraptor or Wazuh active-response path is selected and tested with rollback.

**Goal:** contain and coordinate once something is confirmed.

**Workflow steps:**
1. Triggered when a TheHive case is set to `confirmed_incident`.
2. LLM proposes a containment plan based on the incident narrative (e.g. isolate host, disable account, block IOC at the firewall/EDR) — proposal only, not auto-executed for high-impact actions unless a policy explicitly allows it.
3. Deterministic Shuffle actions execute approved containment steps:
   - Host isolation via Velociraptor or Wazuh active-response.
   - IOC blocking pushed to Wazuh/firewall.
   - Account disable via directory service API, if integrated.
4. Maintains a running timeline directly in the TheHive case (every action, timestamp, and actor — human or agent).
5. Notifies stakeholders (email/Slack/Teams via Shuffle) based on severity.
6. On resolution, hands the case to the **Reporting/QA Agent**.

**Guardrail:** any action with business impact (isolating a production server, disabling a VIP account) requires human approval via a TheHive task or a Shuffle approval step — the agent proposes, a human confirms, execution proceeds. Lower-impact actions (blocking an IOC, adding a detection rule) can be fully automated.

---

## 10. Agent 7 — Reporting / QA Agent

**Status:** Phase 7 complete on 2026-07-12 for digest, QA, TheHive reporting, and CISO email delivery. `scripts/phase7-reporting-qa.ps1` and `shuffle/reporting-qa-agent-ciso.md` are added. Final verification referenced and read back 4 TheHive cases, created JSON/Markdown/email artifacts, sent the digest through Gmail SMTP, and created TheHive reporting case number `8` (`lTVXWZ8BMJtAHxh0N5kg`).

**Goal:** close the loop and improve the system over time.

**Workflow steps:**
1. Triggered on case closure.
2. LLM drafts a post-incident summary from the full TheHive case (timeline, root cause, containment actions, IOCs).
3. Flags potential detection gaps (e.g. "this technique wasn't caught by any Wazuh rule until Tier 2 investigation found it") and creates a task for the Threat Intel Agent to build new content.
4. Aggregates weekly/monthly metrics (MTTD, MTTR, false-positive rate per Wazuh rule) for SOC Manager visibility.
5. **Delivers the final report to the CISO** via the configured channel(s) — see section 14 below.

---

## 14. Final Delivery to CISO (Email / WhatsApp)

**Goal:** every closed case (and the periodic digest) reaches the CISO automatically, without anyone manually copy-pasting a summary.

**Trigger:** last step of the Reporting/QA Agent, after the post-incident summary and metrics are generated. Also runs on the weekly/monthly digest cycle.

**Report content (kept short for a busy exec, full detail stays in TheHive):**
- Case ID, severity, current status (confirmed incident / false positive / monitoring).
- One-paragraph summary of what happened and what was done.
- Key IOCs and affected host/user (only if relevant to the CISO's decision-making, not a raw dump).
- Link to the full TheHive case for anyone who wants the details.
- For the periodic digest: MTTD/MTTR trend, number of cases by severity, top detection gap identified that week.

**Delivery via Email (Shuffle "Email" app):**
1. LLM formats the report content above into a short HTML/plain-text email body (subject line includes severity + case ID, e.g. `[SOC][Critical] Case #1042 — confirmed incident, contained`).
2. Shuffle's native Email app sends it directly via SMTP or an integrated mail provider (e.g. Gmail/Outlook connector) — no extra middleware needed.
3. Attach the full report as a PDF/markdown file if the case is high severity (generate via a simple templating step before send).

**Delivery via WhatsApp (Shuffle + WhatsApp Business API / Twilio):**
1. WhatsApp has stricter formatting limits (no rich HTML) and requires either the official WhatsApp Business Cloud API or a provider like Twilio's WhatsApp API — Shuffle can call either as a generic HTTP action if there's no pre-built app.
2. For anything outside a pre-approved 24-hour conversation window, WhatsApp requires an approved message **template** (Meta's policy) — so pre-register a template like:
   `"SOC Alert: Case {{1}} — {{2}} severity — status: {{3}}. Full report: {{4}}"`
3. The agent fills the template variables (case ID, severity, status, TheHive link) and calls the WhatsApp API via Shuffle's HTTP action.
4. Keep WhatsApp messages to a short alert + link — never send full IOC lists or sensitive details over WhatsApp; the link should route to an authenticated TheHive view.

**Routing logic (which channel, when):**
- `critical` / `confirmed_incident` → send both email (full report) and WhatsApp (short alert, immediate ping) — WhatsApp for urgency, email for the record.
- `high` → email only.
- `medium`/`low`/digest reports → email only, batched into the weekly digest rather than sent individually.

**Config to add:**
- CISO's email address and WhatsApp number stored as Shuffle variables (not hardcoded in the workflow) so they can be rotated without editing agent logic.
- A simple on/off toggle per channel, in case the CISO wants to mute WhatsApp during off-hours and rely on email only.

---

## 11. Shared Data Contracts

To keep agents loosely coupled, standardize on a shared JSON schema passed via TheHive case custom fields and Shuffle variables:

```json
{
  "case_id": "string",
  "host": "string",
  "user": "string",
  "observables": [{"type": "ip|domain|hash|file", "value": "string", "source_agent": "string"}],
  "verdict_history": [
    {"agent": "triage", "verdict": "investigate", "timestamp": "iso8601"},
    {"agent": "investigation", "verdict": "confirmed_incident", "timestamp": "iso8601"}
  ],
  "current_status": "open|monitoring|confirmed_incident|closed"
}
```

Every agent reads the latest state from this object and appends to `verdict_history` rather than overwriting — this gives full auditability and lets a human reconstruct exactly why the automation made each decision.

---

## 12. Guardrails Across All Agents

- **Strict JSON outputs only** from every LLM call — never free text — so Shuffle can branch reliably.
- **Confidence thresholds:** any verdict below a configurable confidence score (e.g. 0.7) auto-routes to a human regardless of what the label says.
- **No agent auto-closes a `critical` severity case** — Triage and Investigation agents can downgrade severity, but only a human or the IR Agent (with approval) can close a critical case.
- **Rate limiting / cost control** on Cortex and CAPEv2 calls — cache recent verdicts for identical hashes/IOCs so the same file isn't sandboxed twice in 24 hours.
- **Full audit trail** in TheHive: every agent action, prompt, and tool call logged as a case observable or task comment.

**Phase 8 status:** Complete on 2026-07-12 for read-only hardening and documentation audit. `scripts/phase8-hardening-audit.ps1` and `shuffle/hardening-documentation-audit.md` are added. Final audit `phase8-evidence/20260712-225441-hardening-audit.json` verified Phase 1-7 script/runbook/evidence coverage and Gmail SMTP config. Findings remain as residual risks: live secrets in `.env` and secret-like local files requiring review before commits/backups.

---

## 13. Suggested Build Order

1. Orchestrator + Triage Agent (biggest immediate time saving, lowest risk).
2. TheHive case schema and shared data contract.
3. Investigation Agent + Velociraptor integration.
4. Malware Analysis Agent (CAPEv2 + MISP push).
5. Threat Intel Agent (feed ingestion + Wazuh rule push).
6. Incident Response Agent (start with proposal-only, no auto-execution).
7. Threat Hunting Agent.
8. Reporting/QA Agent, including CISO email/WhatsApp delivery.

This order lets you get triage automation live and trusted before adding agents with higher blast radius (containment actions, fleet-wide hunts).
