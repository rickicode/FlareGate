# Docker Deployment Guide

This guide explains how to deploy FlareGate using Docker and Docker Compose.

## Quick Start

### Using Docker Hub Image

```bash
# Pull the image
docker pull hijilabs/flaregate:latest

# Run the container
docker run -d \
  --name flaregate \
  -p 8020:8020 \
  -e SECRET_KEY=your-secret-key \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=your-password \
  -v $(pwd)/data:/app/data \
  hijilabs/flaregate:latest
```

### Using Docker Compose

1. Clone the repository:
```bash
git clone https://github.com/yourusername/FlareGate.git
cd FlareGate
```

2. Copy and configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start the application:
```bash
docker-compose up -d
```

4. Access the application at `http://localhost:8020`

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Server Configuration
PORT=8020

# Security
SECRET_KEY=your-very-secret-key-here-change-this
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password-here
```

### Data Persistence

The application stores its SQLite database in the `/app/data` directory. This directory is mounted as a volume to persist data across container restarts.

## Advanced Options

### Using Nginx Reverse Proxy

To use Nginx as a reverse proxy with SSL termination:

1. Copy the nginx configuration:
```bash
cp nginx.conf.example nginx.conf
# Edit nginx.conf for your domain and SSL certificates
```

2. Create SSL directory:
```bash
mkdir ssl
# Place your SSL certificates in ssl/cert.pem and ssl/key.pem
```

3. Start with Nginx profile:
```bash
docker-compose --profile with-nginx up -d
```

### Building Locally

To build the Docker image locally:

```bash
# Build the image
docker build -t flaregate:local .

# Run with local image
docker-compose up -d
```

### Multi-Platform Build

The Dockerfile supports multi-platform builds for AMD64 and ARM64:

```bash
# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t flaregate:latest .
```

## Docker Compose Profiles

### Default Profile
- Runs only the FlareGate application
- Exposes port 8020

### Nginx Profile
- Runs FlareGate + Nginx reverse proxy
- Exposes ports 80 and 443
- Requires SSL certificates in `./ssl/`

To use a profile:
```bash
# Default
docker-compose up -d

# With Nginx
docker-compose --profile with-nginx up -d
```

## Security Considerations

1. **Change Default Credentials**: Always change the default admin username and password
2. **Use Strong SECRET_KEY**: Generate a random, long string for the SECRET_KEY
3. **Network Security**: Consider using internal networks for production
4. **SSL/TLS**: Use HTTPS in production with Nginx or a load balancer

## Health Checks

The Docker image includes a health check that verifies the application is responding:

```bash
# Check health status
docker ps
docker inspect tunnelx | grep Health -A 10
```

## Logs

View application logs:

```bash
# Docker logs
docker logs tunnelx

# Follow logs
docker logs -f tunnelx

# Docker Compose logs
docker-compose logs -f tunnelx
```

## Troubleshooting

### Port Already in Use
If port 8020 is already in use, modify the port mapping in `docker-compose.yml`:
```yaml
ports:
  - "8021:8020"  # Maps container port 8020 to host port 8021
```

### Database Permissions
Ensure the data directory has proper permissions:
```bash
sudo chown -R 1000:1000 ./data
```

### Cloudflared Issues
The Docker image includes cloudflared, but if you need a specific version:
```bash
# Modify Dockerfile to use specific cloudflared version
RUN curl -L --output cloudflared https://github.com/cloudflare/cloudflared/releases/download/2023.8.2/cloudflared-linux-amd64
```

## Updating

To update to the latest version:

```bash
# Pull latest image
docker-compose pull

# Restart containers
docker-compose up -d
```

## Production Deployment

For production deployment, consider:

1. Using Docker secrets for sensitive data
2. Implementing proper backup strategies for the SQLite database
3. Setting up monitoring and alerting
4. Using a container orchestration platform (Kubernetes, Swarm)
5. Implementing CI/CD pipelines

## Support

For issues and questions:
- Create an issue on GitHub
- Check the [documentation](/docs)
- Review the [troubleshooting section](#troubleshooting)