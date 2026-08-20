# Deployment Guide

This project is a homelab reference architecture. It is not a turnkey production deployment.

## Prerequisites

- Docker and Docker Compose
- A Linux host or LXC/VM with enough memory for Wazuh, Shuffle, MISP, TheHive, Cortex, and helper services
- Optional Proxmox environment for CAPE and Windows sandbox VMs
- Optional external Docker network named `vlan50`

## Secrets

1. Copy `.env.example` to `.env`.
2. Replace every `change-me` value with a unique secret.
3. Keep service-specific env files outside Git, usually under `/root/<service>/env` in the SOC Docker host.
4. Never commit Wazuh `client.keys`, API keys, OAuth secrets, CAPE tokens, MISP keys, TheHive keys, or Velociraptor configs.

## Network Model

The reference lab uses:

- `soc-net` for internal Docker service communication.
- `vlan50` as an external network for lab-facing services.
- Proxmox VMs for malware sandboxing and CAPE.

If you do not have this exact network, update `docker-compose.yml` before running the stack.

## Validation

Portable checks:

```bash
docker compose --env-file .env.example config --quiet
```

Live homelab checks from the management workstation:

```powershell
powershell -ExecutionPolicy Bypass -File "scripts\test-soc.ps1" -SkipWazuhRegression
powershell -ExecutionPolicy Bypass -File "scripts\test-wazuh-pfsense-snort.ps1"
```

## Production Safety Notes

- Keep `ACTION_EXECUTOR_MODE=audit_only` unless real containment adapters and rollback procedures are implemented.
- Keep Wazuh remote commands disabled unless you explicitly design and approve that path.
- Treat malware detonation as a controlled operation with sandbox readiness checks, rollback snapshots, and sample-handling procedures.
