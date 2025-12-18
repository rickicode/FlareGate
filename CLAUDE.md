# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is FlareGate - a Go web application that provides a dashboard for managing Cloudflare Tunnel hostnames and ingress rules. It uses the Gin framework, GORM for database operations with SQLite, and Tailwind CSS for the frontend.

## Build and Run Commands

### Development Setup
```bash
# Install dependencies
go mod tidy

# Build the binary
go build -o flaregate

# Run the application
./flaregate
```

### Running in Development
```bash
# Set PORT environment variable (optional, defaults to 8020)
PORT=8020 ./flaregate

# Or with specific environment variables
PORT=8030 SECRET_KEY=mysecret ADMIN_USERNAME=admin ADMIN_PASSWORD=password ./flaregate
```

## Architecture

### Core Components

1. **Main Application** (`main.go`):
   - Web server using Gin framework
   - Session-based authentication with cookie store
   - Embedded templates and static files using embed.FS
   - Auto-starts tunnel if configuration exists

2. **Internal Packages**:
   - `internal/config`: Database models and configuration management using GORM
   - `internal/cloudflare`: HTTP client for Cloudflare API V4
   - `internal/tunnel`: Manages cloudflared process lifecycle (start/stop/restart)

3. **Database**:
   - SQLite database stored at `data/tunnel.db`
   - Single table `configs` storing Cloudflare credentials and tunnel info
   - Auto-migration on startup

4. **Process Management**:
   - Runs cloudflared as external process with token authentication
   - Logs written to `data/cloudflared.log`
   - Concurrent process monitoring with mutex protection

### Key Patterns

- **Configuration Storage**: App config (API tokens, tunnel IDs) persisted in SQLite
- **Session Management**: Cookie-based sessions for admin authentication
- **Process Orchestration**: External cloudflared process managed via Go's os/exec
- **Embedded Assets**: Templates and static files embedded in binary using embed.FS
- **API Integration**: Direct REST API calls to Cloudflare V4 API

### Authentication Flow

1. Admin login via session cookies
2. Cloudflare API token entered in web UI (not stored in env)
3. Token verified and tunnel selected via Cloudflare API
4. Tunnel token generated and stored for cloudflared process

### Data Flow

1. User adds hostname → DNS CNAME created via Cloudflare API
2. Ingress rules updated in tunnel configuration
3. cloudflared process picks up configuration changes
4. External service accessible via Cloudflare tunnel

## Environment Variables

Required `.env` file (copy from `.env.example`):
- `PORT`: Web server port (default: 8020)
- `SECRET_KEY`: Session cookie encryption key
- `ADMIN_USERNAME`: Dashboard admin username
- `ADMIN_PASSWORD`: Dashboard admin password

Note: Cloudflare API token is entered through the web UI, not environment variables.

## Dependencies

- **Go 1.25+**: Core runtime
- **GCC**: Required for CGO (sqlite3 driver)
- **cloudflared**: Cloudflare tunnel client (must be installed in PATH)
- **build-essential**: On Ubuntu/Debian for CGO compilation

## Static Assets

- Templates: `templates/*.html` with partials in `templates/partials/`
- Static files: `static/` (currently only favicon.svg)
- Both embedded in binary using `//go:embed`