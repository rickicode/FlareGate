# Build stage
FROM golang:1.23-bookworm AS builder

# Install build dependencies (none needed for pure Go)
# SSL certs might be needed for download if not in base, but golang image has them.

# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
# CGO_ENABLED=0 is much faster and produces static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o flaregate .

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    sqlite3 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install cloudflared with architecture detection
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        curl -L --output /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64; \
    elif [ "$ARCH" = "arm64" ]; then \
        curl -L --output /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    chmod +x /usr/local/bin/cloudflared

# Create hijilabs user
RUN groupadd -r hijilabs && \
    useradd -r -g hijilabs -d /app -s /bin/bash hijilabs

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/flaregate .

# Create data directory for SQLite database
RUN mkdir -p /app/data && \
    chown -R hijilabs:hijilabs /app

# Switch to non-root user
USER hijilabs

# Expose port
EXPOSE 8020

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8020/ || exit 1

# Run the application
CMD ["./flaregate"]