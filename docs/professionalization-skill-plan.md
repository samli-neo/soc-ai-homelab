# Professionalization Skill Plan

Generated: 2026-08-15

Purpose: make this SOC homelab more professional, aesthetic, recruiter-friendly, and easier to develop further.

## Evidence From Research

- GitHub recommends a README that explains what the project does, why it is useful, how to get started, where to get help, and who maintains it.
- GitHub recognizes root-level README files automatically and supports relative links/images, which makes embedded diagrams and screenshots a strong repository presentation pattern.
- GitHub recommends a `SECURITY.md` policy for vulnerability reporting and security expectations.
- GitHub Pages can host a project site directly from repository HTML/CSS/JS, making `docs/portfolio.html` a good next publishing target.
- GitHub Actions hardening guidance recommends least-privilege `GITHUB_TOKEN` permissions, careful secret handling, avoiding unsafe privileged workflows, and using code scanning/dependency automation.

Sources:

- GitHub README documentation: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes
- GitHub security policy documentation: https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository
- GitHub Pages documentation: https://docs.github.com/en/pages/getting-started-with-github-pages/about-github-pages
- GitHub Actions hardening documentation: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions

## Current Repo Strengths

- Clear root `README.md` with purpose, architecture, guardrails, validation, roadmap, and career relevance.
- `SECURITY.md`, `.env.example`, `.gitignore`, and MIT license are present.
- Draw.io architecture and role-organigram diagrams are available as editable `.drawio` files and SVG previews.
- `docs/portfolio.html` gives the project a visual portfolio surface.
- The repo is private while being prepared for publication.

## Best Skills To Apply Next

### 1. `frontend-design`

Use for the public portfolio site, README visual hierarchy, and a more distinctive design system.

Highest-value upgrades:

- Turn `docs/portfolio.html` into a multi-section project microsite.
- Add sections for architecture, incident workflow, validation evidence, technology stack, and career outcomes.
- Add responsive screenshots, timeline, platform cards, and a visual incident lifecycle.
- Preserve the current cyber/industrial dark visual language but make it more polished and less single-screen.

Expected result: the project feels like a serious engineering case study, not just a code dump.

### 2. `drawio`

Use for professional architecture diagrams, SOC team organigrams, sequence flows, and deployment maps.

Highest-value upgrades:

- Add a third diagram: `incident-lifecycle.drawio` from alert to case to enrichment to approval to reporting.
- Add a fourth diagram: `deployment-topology.drawio` showing Proxmox, Docker LXC, VLAN, sandbox VMs, and internal service boundaries.
- Keep both editable `.drawio` and embedded SVG exports.

Expected result: recruiters and engineers can understand the system in 30 seconds.

### 3. `github-ops`

Use for repo metadata, topics, releases, Issues, Projects, branch protection, GitHub Pages, and public-readiness workflow.

Highest-value upgrades:

- Add repository topics: `soc`, `siem`, `soar`, `wazuh`, `thehive`, `misp`, `cortex`, `capev2`, `velociraptor`, `malware-analysis`, `dfir`, `security-automation`.
- Enable GitHub Pages from `docs/` after final review.
- Create a first release `v0.1-private-portfolio` after security review.
- Add curated issues for the roadmap.

Expected result: the GitHub repo looks maintained, searchable, and intentional.

### 4. `security-review`

Use before making the repo public.

Highest-value upgrades:

- Run a strict secret review over all source/config/docs.
- Review `PROJECT_MEMORY.md` for private operational details, internal IPs, usernames, or incident-specific artifacts.
- Confirm all token values were rotated after prior exposure.
- Add a public-safe disclosure note explaining that secrets and malware samples are excluded.

Expected result: public release without leaking credentials or sensitive homelab details.

### 5. `deployment-patterns`

Use to make the stack more reproducible and professional.

Highest-value upgrades:

- Split Compose into profiles: `core`, `malware`, `dfir`, `portfolio-demo`.
- Replace absolute `/root/...` paths with documented variables or profile overlays.
- Add `docs/deployment.md` with prerequisites, networking, secrets, and validation.

Expected result: other engineers can reason about the deployment without your exact homelab.

### 6. `ai-regression-testing`

Use for CI and validation credibility.

Highest-value upgrades:

- Add GitHub Actions syntax checks for Python services and PowerShell parser checks.
- Add XML validation for Wazuh rules/decoders and Draw.io files.
- Add Compose config validation with `.env.example`.
- Add tests that avoid live secrets and external dependencies.

Expected result: a green CI badge that proves engineering discipline.

### 7. `dashboard-builder`

Use to make the operator dashboard more useful and visually credible.

Highest-value upgrades:

- Add screenshots and documented panels for intake count, workflow health, semantic failures, approval backlog, and malware pipeline state.
- Add an operator questions section: what is broken, what needs approval, what needs analyst review, what is safe to ignore.

Expected result: the dashboard answers real SOC operator questions.

### 8. `seo`

Use once the repo or GitHub Pages site is public.

Highest-value upgrades:

- Add meta title/description/Open Graph tags to `docs/portfolio.html`.
- Add structured headings and a clean project summary optimized for searches like “SOC automation homelab”, “Wazuh Shuffle TheHive MISP project”, and “cybersecurity portfolio project”.
- Add image alt text and social preview assets.

Expected result: better discoverability by recruiters and search engines.

### 9. `content-engine` + `brand-voice`

Use for LinkedIn/GitHub profile publishing.

Highest-value upgrades:

- Write a concise launch post for LinkedIn.
- Create a GitHub profile README section pointing to the project.
- Create a 5-post build-in-public sequence: architecture, Wazuh detection, SOAR workflow, malware pipeline, lessons learned.

Expected result: the project helps with job search, not just GitHub storage.

### 10. `project-flow-ops`

Use to turn the roadmap into visible execution.

Highest-value upgrades:

- Create GitHub Issues for each roadmap item.
- Label issues by area: `design`, `security`, `ci`, `docs`, `detection`, `malware`, `dfir`.
- Track next public-release blockers in a GitHub Project board.

Expected result: the repo looks actively managed and easy to continue.

## Recommended Execution Order

1. Security review and redaction pass.
2. GitHub repo metadata, topics, and issue roadmap.
3. GitHub Pages portfolio site from `docs/portfolio.html`.
4. Design pass on the portfolio site using `frontend-design`.
5. Add deployment and incident lifecycle diagrams with `drawio`.
6. Add CI validation with safe offline checks.
7. Improve README into a tighter case study.
8. Add LinkedIn/GitHub launch content.
9. Make the repo public only after token rotation and final review.

## Public-Release Checklist

- [ ] Rotate any token that appeared in local config or tool output.
- [ ] Review `PROJECT_MEMORY.md` for sensitive details.
- [ ] Confirm no `.env`, samples, reports, or live keys are tracked.
- [ ] Run the literal secret-pattern scan.
- [ ] Run Compose validation with `.env.example`.
- [ ] Run Wazuh XML fragment validation.
- [ ] Verify README images render on GitHub.
- [ ] Enable GitHub Pages only after the repo is safe for public viewing.
- [ ] Add topics and a release.
- [ ] Publish a short LinkedIn post linking to the repo.
