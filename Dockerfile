# Build stage
FROM golang:1.23-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y gcc libc6-dev sqlite3 pkg-config && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies (this layer only changes when go.mod changes)
RUN go mod download

# Copy source code (this layer changes when source changes)
COPY . .

# Create .cache directory for go build cache
RUN mkdir -p /.cache && chmod 777 /.cache

# Build the application with optimizations
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o flaregate .

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

# Install cloudflared from Cloudflare repository
RUN apt-get update && apt-get install -y --no-install-recommends \
    gpg \
    wget \
    && wget -qO - https://pkg.cloudflare.com/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/cloudflare-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared bookworm main" | tee /etc/apt/sources.list.d/cloudflared.list \
    && apt-get update && apt-get install -y cloudflared \
    && apt-get remove -y gpg wget \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

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