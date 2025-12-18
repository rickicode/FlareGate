# Configuration

FlareGate no longer requires `.env` files. All configuration can be done through environment variables or by using the defaults.

## Environment Variables

### Optional Environment Variables

- **PORT** (default: `8020`)
  - Port for the web server
  - Example: `export PORT=3000` or `PORT=3000 ./flaregate`

- **SECRET_KEY** (auto-generated if not set)
  - Session encryption key
  - If not set, a secure random key will be generated and saved to `data/secret.key`
  - Example: `export SECRET_KEY="your-very-secret-key"`

## Usage Examples

### Basic Usage (Recommended)
```bash
# Use default settings (PORT=8020, auto-generated SECRET_KEY)
./flaregate
```

### Custom Port
```bash
# Use port 3000
PORT=3000 ./flaregate

# Or export for persistent usage
export PORT=3000
./flaregate
```

### Custom Secret Key
```bash
# Use custom secret key
SECRET_KEY="my-very-secure-secret-key" ./flaregate

# Or export for persistent usage
export SECRET_KEY="my-very-secure-secret-key"
./flaregate
```

### Docker Usage
```yaml
# docker-compose.yml
services:
  flaregate:
    image: flaregate:latest
    ports:
      - "8020:8020"
    environment:
      - PORT=8020  # Optional
      - SECRET_KEY=your-secret-key  # Optional
    volumes:
      - ./data:/app/data
```

## First-Time Setup

1. **Run the application**
   ```bash
   ./flaregate
   ```

2. **Open your browser** and go to the displayed URL (default: http://localhost:8020)

3. **Create your admin account**:
   - You'll be automatically redirected to the registration page
   - Fill in your username and password
   - After registration, you'll be logged in automatically

4. **Your account is now ready** for managing Cloudflare tunnels!

## Data Persistence

- **Database**: `data/tunnel.db` - SQLite database for configurations and user account
- **Secret Key**: `data/secret.key` - Auto-generated session encryption key
- **Logs**: `data/cloudflared.log` - Cloudflared process logs

## Security Notes

- **SECRET_KEY** is automatically generated and stored securely in `data/secret.key`
- **Password hashing** uses bcrypt with strong salts
- **Single-user system** - Only one account can be created
- **Session cookies** are secure and HttpOnly
- **No sensitive data** is stored in environment variables by default

## Troubleshooting

### Port Already in Use
```bash
# Find what's using the port
fuser -k 8020/tcp

# Or use a different port
PORT=8030 ./flaregate
```

### Permission Issues (Docker)
```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./data
chmod -R 755 ./data
```