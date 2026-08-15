# Security

This repository is published as a personal SOC automation portfolio project.

Do not commit:

- `.env` files or live API keys
- Wazuh `client.keys` or API credentials
- TheHive, Cortex, MISP, CAPE, Velociraptor, Telegram, OpenRouter, GitHub, or Proxmox tokens
- Malware samples, CAPE reports containing samples, or private incident evidence
- Local screenshots that expose hostnames, emails, tokens, or private IP plans beyond examples

Before making the repository public, rotate any token that was ever present in local config or console output.

The current repository is designed to run with local secret files mounted outside Git, usually under `/root/<service>/env` in the SOC Docker LXC.
