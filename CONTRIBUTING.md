# Contributing

This is a personal cybersecurity homelab portfolio, but contributions and suggestions are welcome.

## Ground Rules

- Do not commit real secrets, tokens, `.env` files, malware samples, or private incident evidence.
- Keep high-risk response actions approval-gated by default.
- Prefer small, reviewable changes with clear validation evidence.
- Update documentation when architecture, deployment, or guardrails change.

## Local Validation

Run these checks before opening a pull request:

```powershell
docker compose --env-file .env.example config --quiet
powershell -NoProfile -ExecutionPolicy Bypass -Command "[xml]('<root>' + (Get-Content -LiteralPath 'configs\wazuh-manager\agent.conf' -Raw) + '</root>') | Out-Null"
```

For live homelab validation, use the scripts in `scripts/` only after configuring local secrets outside Git.

## Security Reports

Use `SECURITY.md` for reporting sensitive issues.
