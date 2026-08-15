# TheHive Case Templates and Dashboards

## Official Documentation Findings

- Official TheHive 5 case-template guidance says templates streamline case creation by pre-filling fields, preserving consistent descriptions, saving analyst time, and enriching ongoing cases. Templates should be based on threat category for effectiveness and continuous improvement.
- Official TheHive 5 case-template creation fields include prefix, name, display name, TLP, PAP, severity, tags, description, tasks, custom fields, and pages. The required permission is `manageCaseTemplate`; created templates are available to all users in the organization.
- Official dashboard guidance says dashboards can be created from scratch or duplicated, assigned a group/title/description, made private or shared with the organization, and populated with widgets.
- Official dashboard widgets include row, bar, donut, line, radar, counter, text, gauge, and table widgets. Row widgets group other widgets, with up to three widgets per row. Bar, donut, line, counter, text, gauge, and table widgets support entity, period/date fields, filters, and aggregation-style options depending on type.
- Official TheHive 5 case report template guidance says report templates generate case-description reports in a predefined format for faster action, collaboration, audit records, and historical analysis. The required permission is `manageCaseReportTemplate`, and the documentation marks this feature as Platinum.
- Case report templates include fixed customizable header/footer sections plus draggable widgets. Supported TheHive 5 report widgets include text, image, table, list, timeline, comments, and pages; text/header/footer fields can use case variables and Mustache/Handlebars helpers such as `tlpLabel`, `papLabel`, `severityLabel`, and `dateFormat`.

Sources:

- `https://docs.strangebee.com/thehive/user-guides/organization/configure-organization/manage-templates/case-templates/about-case-templates/`
- `https://docs.strangebee.com/thehive/user-guides/organization/configure-organization/manage-templates/case-templates/create-a-case-template/`
- `https://docs.strangebee.com/thehive/user-guides/analyst-corner/dashboard/about-dashboards/`
- `https://docs.strangebee.com/thehive/user-guides/analyst-corner/dashboard/widgets-dashboards/`
- `https://docs.strangebee.com/thehive/user-guides/analyst-corner/dashboard/create-a-dashboard/`
- `https://docs.strangebee.com/thehive/user-guides/organization/configure-organization/manage-templates/case-report-templates/about-case-report-templates/`
- `https://docs.strangebee.com/thehive/user-guides/organization/configure-organization/manage-templates/case-report-templates/create-a-case-report-template/`
- `https://docs.strangebee.com/thehive/user-guides/organization/configure-organization/manage-templates/case-report-templates/widgets-case-report-templates/`

## Live Deployment Notes

- Live TheHive is `3.5.2`; API shape differs from current TheHive 5 docs.
- Case-template creation endpoint: `POST /api/v1/case/template` through `thehive-api-compat`.
- Case-template search endpoint: `POST /api/v1/case/template/_search`.
- Dashboard endpoint: `GET/POST /api/v1/dashboard`.
- TheHive 3 dashboard `definition` must be submitted as a JSON string, even though bundled migration examples store the same shape as JSON objects.
- TheHive 3 does not accept the TheHive 5 `displayName` field on case templates.
- Dashboard widgets were limited to TheHive 3-compatible `container`, `donut`, `bar`, and `line` widgets based on bundled examples in `/opt/thehive/migration/12/dashboards/`.
- Native case report templates are not exposed by the live TheHive 3.5.2 deployment. Probable report-template paths such as `/api/v1/case/report/template`, `/api/v1/caseReportTemplate`, `/api/v1/report/template`, `/api/v1/template/report`, `/api/v1/reportTemplate`, and `_search` variants returned `404` through the compatibility API. The live image also has no matching report-template route strings or bundled report-template files under `/opt/thehive`; only dashboard migrations were present.

## Created Case Templates

- `snort_ids`: Snort IDS investigation, signature validation, source/target scoping, enrichment, approval gates, and closure.
- `pfsense_firewall`: pfSense repeated-block/firewall pattern investigation with explicit proposal-only containment guardrail.
- `malware_hash`: Malware hash and CAPEv2 report lookup workflow with detonation approval gate.
- `authentication`: Suspicious authentication workflow for logon, VPN, MFA, and account-activity review.
- `generic_wazuh`: Generic Wazuh triage workflow for alerts that do not match a specific playbook.

All templates include TLP/PAP, severity, tags, Markdown descriptions, tasks, and `metrics: {}`.

## Created Dashboards

- `SOC Case Operations`: shared dashboard with 3 rows and 9 widgets covering open cases by owner, case status/severity, template/SLA/TLP tags, weekly severity/owner history, and case creation trend.
- `SOC Alert Intake`: shared dashboard with 3 rows and 9 widgets covering alert status, waiting alert type/source, severity, SOC template tags, approval-gated alerts, weekly alert type/source history, and alert creation trend.

## Case Report Templates

- No native case report templates were created because this live TheHive 3.5.2 Community deployment does not expose the TheHive 5 Platinum case-report-template capability.
- The existing Markdown report sources remain the supported reporting templates for this lab: `docs/soc/reports/operational-report-template.md` and `docs/soc/reports/executive-report-template.md`.
- If the deployment is upgraded to a TheHive edition/version with `manageCaseReportTemplate`, create native report templates from those Markdown sources using header/footer text plus table/list/timeline widgets for observables, alerts, tasks, comments, and case timeline data.

## Verification

- Templates verified through `POST /api/v1/case/template/_search`.
- Dashboards verified through `GET /api/v1/dashboard`.
- Dashboard read-back confirmed both SOC dashboards have `status=Shared`, `rows=3`, and `widgets=9`.
- Report-template support check verified absence of live support through `404` responses on probable API paths and no report-template strings/files in the running TheHive 3.5.2 image.
