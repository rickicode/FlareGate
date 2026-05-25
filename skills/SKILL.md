---
name: flaregate
description: Manage Cloudflare Tunnel + DNS for NAT VPS via CLI or web dashboard — provision, list, remove hostnames.
version: 2.0.0
category: devops
metadata:
  hermes:
    tags: [cloudflare, tunnel, dns, vps, nat, provisioning]
---

# FlareGate

Single-binary Go app for managing Cloudflare Tunnel hostnames and ingress rules on NAT VPS. Web dashboard + CLI mode. AI agent (Hermes/Claude) integration is a convenience layer — the core product works standalone via CLI or browser.

## Quick start

```bash
# Build (Go 1.24+)
cd /workspaces/FlareGate
go build -ldflags="-w -s" -o flaregate .

# Run dashboard (default, port 8020)
PORT=8020 ./flaregate

# CLI mode — any argument triggers CLI
./flaregate status
./flaregate hostname list
```

## CLI commands

```bash
flaregate status                          # Show config, tunnel, hostnames
flaregate hostname list                   # List all hostnames
flaregate provision <hostname> <target>   # Create DNS + ingress for hostname
flaregate hostname remove <hostname>      # Remove hostname + DNS cleanup
flaregate token                           # Print cloudflared run command
flaregate help                            # Full usage
```

### CLI examples

```bash
flaregate provision app.example.com localhost:3000
flaregate provision api.hijitoko.com 127.0.0.1:8080
flaregate hostname remove old.hijitoko.com
```

CLI reads Cloudflare token and config directly from SQLite — no login required.

## Web dashboard

```
http://localhost:8020
```

First run: register user → setup wizard → enter Cloudflare API token → select tunnel.

Features:
- Add/edit/delete hostname routes with live domain picker
- Real-time tunnel health check + per-service status
- Docker container picker for origin services
- System hostname management
- Cloudflared install modal (auto-detect Docker vs binary, sudo password support for systemd service)
- Change tunnel / reset config

## Architecture

- `main.go` — web server (Gin) + CLI dispatcher + PASETO auth + API endpoints
- `cli.go` — CLI command handlers
- `internal/cloudflare/` — Cloudflare V4 API client with zone resolution, DNS, ingress
- `internal/config/` — SQLite config store with AES-GCM encryption for tokens
- `internal/tunnel/` — cloudflared process lifecycle
- `scripts/flaregate-provision.py` — standalone Python provisioner

## Auth

PASETO v4 local (symmetric):
- Key regenerated each restart → tokens invalidate on restart
- HttpOnly cookie (`paseto_token`) + Bearer header support
- 7-day expiry

## Security

- `APIToken` & `TunnelToken` encrypted at rest (AES-GCM, key from `data/secret.key`)
- Secret key generation fail-closed (no insecure default fallback)
- Tokens excluded from JSON serialization (`json:"-"`)
- No debug endpoints in production

## Cloudflare API token requirements

```
Zone:DNS:Edit     — for the target zone
Account:Cloudflare Tunnel:Edit — for tunnel management
```

## File layout

```
/workspaces/FlareGate/
├── flaregate           # Binary (build output)
├── main.go             # Server + auth + helpers
├── cli.go              # CLI commands
├── go.mod / go.sum
├── internal/
│   ├── cloudflare/     # CF API client
│   ├── config/         # DB + encryption
│   └── tunnel/         # cloudflared runner
├── scripts/
│   └── flaregate-provision.py
├── templates/          # HTML templates
├── static/             # Static assets
├── skills/
│   └── SKILL.md        # Agent skill definition (Hermes/Claude)
└── data/               # Runtime data (auto-created)
    ├── tunnel.db       # SQLite config
    ├── secret.key      # SECRET_KEY
    └── cloudflared.log
```

## Agent interaction pattern

When user invokes FlareGate via AI agent (Hermes, Claude Code, etc.), the agent should:

1. **Hostname/domain:** ask what domain
2. **Target:** ask what ip:port or URL to forward to

Then execute:

```bash
cd /workspaces/FlareGate && ./flaregate provision <hostname> <target>
```

For cloudflared installation, use the web dashboard's built-in install modal (click Health Status card) or follow the manual CLI steps below.

## Installing cloudflared (Cloudflare Tunnel client)

### Step 1: Get tunnel token

```bash
cd /workspaces/FlareGate && ./flaregate token
```

### Step 2: Install cloudflared

**Debian/Ubuntu (x86_64):**
```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cloudflared.deb
sudo dpkg -i /tmp/cloudflared.deb
rm /tmp/cloudflared.deb
```

**CentOS/RHEL/Fedora (x86_64):**
```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-x86_64.rpm -o /tmp/cloudflared.rpm
sudo rpm -ivh /tmp/cloudflared.rpm
rm /tmp/cloudflared.rpm
```

**Standalone binary (any Linux):**
```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /tmp/cloudflared
sudo install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared
rm /tmp/cloudflared
```

### Step 3: Install as systemd service

```bash
sudo cloudflared service install <TOKEN>
sudo systemctl status cloudflared
sudo systemctl enable cloudflared
```

### Troubleshooting

```bash
sudo journalctl -u cloudflared -f   # logs
sudo systemctl restart cloudflared  # restart
which cloudflared                   # check binary
```
