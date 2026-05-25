# FlareGate

A lightweight, high-performance dashboard + CLI to manage Cloudflare Tunnel hostnames and ingress rules on NAT VPS. Built with **Go** and **Tailwind CSS** — single binary, no dependencies.

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go" alt="Go version">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
</p>

## ✨ Features

- **Single Binary** — compiles into one executable, deploy anywhere
- **CLI Mode** — provision, list, remove hostnames without opening a browser
- **Web Dashboard** — beautiful dark UI with real-time health checks
- **Auto DNS + Ingress** — one click to map a domain to a local service
- **Cloudflared Install Modal** — auto-detect Docker/binary mode, install + systemd service with sudo password support
- **Security Hardened** — AES-256-GCM token encryption, bcrypt passwords, PASETO v4 auth
- **Docker Ready** — multi-stage build with cloudflared pre-installed
- **Python Provision Script** — dependency-free helper for minimal VPS images
- **SQLite Storage** — all config encrypted at rest, no external DB needed

## 🚀 Quick Start

### CLI mode (no browser, single command)

```bash
cd /workspaces/FlareGate
./flaregate provision app.example.com localhost:3000
```

### Web dashboard

```bash
./flaregate
# Open http://localhost:8020 → register → enter Cloudflare token → done
```

First run shows registration page. After setup, the dashboard manages everything.

## 📋 CLI Commands

```bash
flaregate provision <hostname> <target>    # Create DNS + tunnel ingress
flaregate hostname list                    # List all configured hostnames
flaregate hostname remove <hostname>       # Remove hostname + DNS cleanup
flaregate status                           # Show config, tunnel, health
flaregate token                            # Print cloudflared run command
flaregate help                             # Full usage
```

**Examples:**
```bash
flaregate provision app.hijitoko.com localhost:3000
flaregate provision api.example.com 127.0.0.1:8080
flaregate hostname remove old.example.com
```

CLI reads encrypted config from SQLite — no login required.

## ☁️ Cloudflared Installation

### Via Web Dashboard (recommended)

1. Open `http://localhost:8020`
2. Click the **Health Status card** (Running/Stopped)
3. Modal auto-detects:
   - **Docker mode** → cloudflared already in image → "Start cloudflared" button
   - **Binary mode** → OS detection + sudo password input → auto download + install + systemd service
4. Progress log shown in real-time

### Via CLI (manual)

```bash
flaregate token
# Output: cloudflared tunnel run --token <TOKEN>

# Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /tmp/cf
sudo install -m 755 /tmp/cf /usr/local/bin/cloudflared
rm /tmp/cf

# Install as systemd service
sudo cloudflared service install <TOKEN>
sudo systemctl enable --now cloudflared
```

## ⚡ Python Provision Script (NAT VPS helper)

Dependency-free, runs on minimal VPS images:

```bash
python3 scripts/flaregate-provision.py
```

Interactive flow: ask token → hostname → target → auto create tunnel + DNS + ingress.

Non-interactive:
```bash
python3 scripts/flaregate-provision.py \
  --hostname app.example.com \
  --target 127.0.0.1:3000 \
  --token "$CLOUDFLARE_API_TOKEN"
```

State files saved under `~/.local/share/flaregate/` with `chmod 600`.

## 🐳 Docker

```bash
docker build -t flaregate .
docker run -d -p 8020:8020 -v $(pwd)/data:/app/data flaregate
```

Dockerfile includes cloudflared pre-installed. Health card modal shows "Start cloudflared" directly.

## 🛡️ Security

| Layer | Implementation |
|---|---|
| API Token storage | AES-256-GCM encrypted in SQLite |
| Tunnel Token storage | AES-256-GCM encrypted |
| User password | bcrypt hashed |
| Session auth | PASETO v4 local (symmetric), 7-day expiry |
| Cookie | HttpOnly, auto-invalidated on restart |
| API tokens | `json:"-"` — never serialized |
| Secret key | Generated on first run, stored in `data/secret.key` (0600) |
| Encryption key | SHA-256 derived from secret key |
| Nonce | Random per encryption (crypto/rand) |
| Input validation | FQDN hostname check, service format check |

**Required Cloudflare API token permissions:**
```
Zone:DNS:Edit
Account:Cloudflare Tunnel:Edit
```

## 🔧 Build

```bash
# Prerequisites: Go 1.24+
cd /workspaces/FlareGate
go mod tidy
go build -ldflags="-w -s" -o flaregate .
```

## 📂 Project Structure

```
├── main.go                   # Web server + auth + API endpoints
├── cli.go                    # CLI command dispatcher
├── go.mod / go.sum
├── Dockerfile                # Multi-stage with cloudflared
├── Makefile
├── internal/
│   ├── cloudflare/client.go  # Cloudflare V4 API client
│   ├── config/config.go      # SQLite store + AES-GCM encryption
│   └── tunnel/runner.go      # cloudflared process lifecycle
├── scripts/
│   └── flaregate-provision.py
├── templates/                # Go HTML templates
├── static/                   # Static assets
└── data/                     # Runtime data (auto-created)
    ├── tunnel.db             # SQLite config
    ├── secret.key            # Encryption key (0600)
    └── cloudflared.log
```

## 🔗 Related

- [Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
- [Cloudflare API tokens](https://dash.cloudflare.com/profile/api-tokens)

---

*Built with ❤️ by HIJILABS*
