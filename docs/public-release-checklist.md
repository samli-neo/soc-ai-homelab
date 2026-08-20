# Public Release Checklist

Use this checklist before making the repository public or enabling GitHub Pages.

## Required Before Public Release

- Rotate any token that may have appeared in local terminal output, screenshots, notes, or tool configuration.
- Confirm `.env`, service env files, API keys, OAuth secrets, Wazuh `client.keys`, malware samples, and private evidence are not tracked.
- Review `PROJECT_MEMORY.md` for private IPs, hostnames, workflow IDs, internal recovery notes, or sensitive operational details.
- Review screenshots in `docs/assets/` for browser account details, private URLs, tokens, alerts, or incident evidence.
- Run `docker compose --env-file .env.example config --quiet` successfully.
- Run the repository CI checks successfully on GitHub Actions.
- Confirm `SECURITY.md` gives safe reporting guidance and does not expose contact details that should remain private.
- Confirm high-risk automation remains disabled, audit-only, or approval-gated by default.

## Optional Before Public Release

- Enable GitHub Pages from the `docs/` folder.
- Add a pinned portfolio link to the GitHub repository description.
- Add a short demo video or GIF that uses sanitized data only.
- Add architecture screenshots exported from Draw.io after any diagram updates.

## Release Decision

Do not make the repository public until every required item is complete.
